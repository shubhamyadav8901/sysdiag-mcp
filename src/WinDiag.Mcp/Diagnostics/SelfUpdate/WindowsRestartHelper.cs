using System.Diagnostics;
using System.Management;
using System.Runtime.Versioning;
using System.Text;
using Diag.Mcp.Server.SelfUpdate;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using WinDiag.Mcp.Configuration;

namespace WinDiag.Mcp.Diagnostics.SelfUpdate;

/// <summary>The Windows swap: a detached .cmd helper that waits for this process, re-verifies, moves, restarts.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsRestartHelper : IRestartHelper
{
    private readonly WinDiagOptions _options;
    private readonly ILogger<WindowsRestartHelper> _logger;

    public WindowsRestartHelper(WinDiagOptions options, ILogger<WindowsRestartHelper> logger)
    {
        _options = options;
        _logger = logger;
    }

    /// <summary>
    /// The command the helper uses to bring the server back after the swap.
    /// </summary>
    /// <param name="serviceName">This process's service name, or null when it was started by hand.</param>
    /// <remarks>
    /// <para>A server registered with the Service Control Manager cannot be restarted by launching its
    /// executable. That starts a process the SCM knows nothing about: the service reads as Stopped while
    /// something is listening on its port, <c>service_control start</c> then fails because the port is
    /// taken, and the machine is in a state nobody looking at it would predict. Exactly the kind of
    /// confident-but-wrong picture this project exists to avoid.</para>
    /// <para><c>sc start</c> is tolerant of the service already running -- if the SCM's own recovery
    /// action restarted it first, this is a harmless no-op rather than a race.</para>
    /// <para>Separated from the script builder so both branches can be tested, since neither can be
    /// exercised by running the suite: one needs a registered service and the other relaunches the
    /// test host.</para>
    /// </remarks>
    internal static string RelaunchCommand(string? serviceName, string live, string arguments) =>
        string.IsNullOrWhiteSpace(serviceName)
            ? $"start \"windiag\" \"{live}\" {arguments}"
            : $"sc start \"{serviceName}\"";

    /// <summary>
    /// This process's own service name, or null when it is not running as one.
    /// </summary>
    /// <remarks>
    /// Asked for by process id rather than configured, so nothing has to be kept in step with the
    /// registration -- and it must be asked NOW, while the process still exists: by the time the helper
    /// runs, the lookup would find nothing. A failure here is deliberately non-fatal and falls back to
    /// launching the executable, which is the behaviour every by-hand deployment already has.
    /// </remarks>
    private string? OwnServiceName()
    {
        if (!WindowsServiceHelpers.IsWindowsService())
        {
            return null;
        }

        // Asked of the environment first, because --install-service puts it there and the answer is
        // then exact and free. The WMI query below is the fallback for a service somebody registered by
        // hand, and it is genuinely a fallback: on a real service it threw rather than answering, which
        // is how this came to be written the other way round.
        var configured = Environment.GetEnvironmentVariable("WINDIAG_SERVICE_NAME");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }

        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT Name FROM Win32_Service WHERE ProcessId = {Environment.ProcessId}");

            using var results = searcher.Get();
            foreach (var row in results)
            {
                using (row)
                {
                    return row["Name"] as string;
                }
            }
        }
        catch (Exception ex)
        {
            // Every exception, deliberately. This lookup only decides HOW to restart; failing it must
            // never fail the update. Catching just ManagementException was not enough -- on a real
            // service the query threw something else and took update_self down with it, turning a
            // best-effort enrichment into the thing that broke the critical path. The fallback is the
            // behaviour every by-hand deployment already has.
            _logger.LogWarning(
                ex,
                "running as a service but could not determine the service name ({Type}); will relaunch "
                + "the executable instead",
                ex.GetType().Name);
        }

        return null;
    }

    /// <summary>Writes and starts the helper that performs the swap once this process has exited.</summary>
    /// <remarks>
    /// The helper inherits this process's environment, so the relaunched server keeps its token without
    /// it ever being written to disk. It re-verifies the hash before moving, because the window between
    /// this check and the swap is one an attacker with file access could otherwise use.
    /// </remarks>
    public void Launch(string live, string staged, string sha256, string log)
    {
        var helper = Path.Combine(_options.ArtifactDirectory, "self-update.cmd");
        var arguments = string.Join(' ', Environment.GetCommandLineArgs().Skip(1).Select(Quote));
        var relaunch = RelaunchCommand(OwnServiceName(), live, arguments);

        var script = new StringBuilder()
            .AppendLine("@echo off")
            .AppendLine("setlocal enabledelayedexpansion")
            .AppendLine($">\"{log}\" echo [%date% %time%] self-update starting for PID {Environment.ProcessId}")
            .AppendLine(":waitforexit")
            .AppendLine($"tasklist /FI \"PID eq {Environment.ProcessId}\" 2>nul | find \"{Environment.ProcessId}\" >nul")
            // ping, not timeout: timeout.exe needs a console and this helper is started with
            // CreateNoWindow, so where it has none it fails instantly and the loop becomes a hot spin.
            // That was invisible while the wait was only ever a few seconds; with a drain the loop can
            // now run for minutes, which would be a pegged core and a tasklist storm.
            .AppendLine("if not errorlevel 1 (ping -n 2 127.0.0.1 >nul & goto waitforexit)")
            .AppendLine($">>\"{log}\" echo [%time%] server exited; re-verifying")

            // Cleared first, and deliberately. "if not defined" never assigns when the variable is
            // already set, and this helper inherits its environment from the server -- which was itself
            // started by the PREVIOUS helper, which left this variable set. Without the reset each
            // update compares against the hash from the update before it, so the mechanism poisons
            // itself forward and every second update refuses a mismatch that is not real.
            .AppendLine("set \"WINDIAG_STAGED_HASH=\"")
            .AppendLine($"for /f \"skip=1 tokens=* delims=\" %%H in ('certutil -hashfile \"{staged}\" SHA256') do (")
            .AppendLine("  if not defined WINDIAG_STAGED_HASH set \"WINDIAG_STAGED_HASH=%%H\"")
            .AppendLine(")")
            .AppendLine("set \"WINDIAG_STAGED_HASH=!WINDIAG_STAGED_HASH: =!\"")
            .AppendLine($"if /i not \"!WINDIAG_STAGED_HASH!\"==\"{sha256}\" (")
            .AppendLine($"  >>\"{log}\" echo [%time%] ABORT hash mismatch: !WINDIAG_STAGED_HASH!")

            // A failed update must NOT leave the machine with no server. The live executable is
            // untouched at this point, so put it back up -- otherwise a refused update costs a trip to
            // the console, which is the exact thing this mechanism exists to avoid.
            .AppendLine($"  >>\"{log}\" echo [%time%] restarting the existing build instead")
            .AppendLine($"  {relaunch}")
            .AppendLine("  exit /b 2")
            .AppendLine(")")
            .AppendLine($"move /y \"{staged}\" \"{live}\" >nul")
            .AppendLine("if errorlevel 1 (")
            .AppendLine($"  >>\"{log}\" echo [%time%] ABORT move failed; restarting the existing build")
            .AppendLine($"  {relaunch}")
            .AppendLine("  exit /b 3")
            .AppendLine(")")
            .AppendLine($">>\"{log}\" echo [%time%] swapped; relaunching")
            .AppendLine($"{relaunch}")
            .AppendLine($">>\"{log}\" echo [%time%] done")
            .ToString();

        WriteScript(helper, script);

        // Removed rather than left for cmd's ">" to truncate, for the reason WriteScript gives: a log a user
        // left here would keep their ownership, and a link at that name would aim SYSTEM's writes elsewhere.
        File.Delete(log);

        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c \"{helper}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(live)!
        });

        _logger.LogInformation("self-update helper started, logging to {Log}", log);
    }

    /// <summary>Writes <paramref name="script"/> to <paramref name="path"/> as a file this call creates.</summary>
    /// <remarks>
    /// <para>Deleted and created anew, never opened and truncated. Truncating keeps the file that is
    /// there -- its owner, its DACL and every handle already open on it -- and an artifact directory an
    /// older build left writable by every user may hold a self-update.cmd a user made. Its owner can grant
    /// itself write access whatever the directory says, and cmd re-reads a batch file line by line while
    /// the helper waits for the server to exit, so a rewrite there runs as SYSTEM.</para>
    /// <para><see cref="FileMode.CreateNew"/>, so if anything is at that name again by the time the
    /// file is created -- which needs write access to the directory -- the update fails instead of
    /// writing into it.</para>
    /// </remarks>
    internal static void WriteScript(string path, string script)
    {
        File.Delete(path);
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        var bytes = Encoding.ASCII.GetBytes(script);
        file.Write(bytes);
    }

    private static string Quote(string argument) =>
        argument.Contains(' ', StringComparison.Ordinal) ? $"\"{argument}\"" : argument;
}
