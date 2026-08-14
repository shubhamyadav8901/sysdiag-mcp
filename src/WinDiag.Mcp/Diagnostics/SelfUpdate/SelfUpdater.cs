using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.Signatures;

namespace WinDiag.Mcp.Diagnostics.SelfUpdate;

/// <summary>
/// Installs a staged build by handing the swap to a detached helper and then exiting.
/// </summary>
/// <remarks>
/// <para>Exists because file copy is the only channel some targets offer. On a lab VM reachable by SMB
/// but not by WinRM or DCOM, a new binary can be delivered but nothing can stop the process holding the
/// old one open — so every update needed someone at the console.</para>
/// <para><strong>This is the most dangerous code in the project.</strong> It replaces an executable that
/// runs elevated and starts it again, so a caller holding the bearer token could otherwise run anything
/// as SYSTEM. Three things constrain it: the tool is not registered unless explicitly enabled, the
/// caller must state the exact hash they expect, and a signed server will only accept a validly signed
/// replacement.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class SelfUpdater : ISelfUpdater
{
    private readonly ISignatureInspector _signatures;
    private readonly WinDiagOptions _options;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger<SelfUpdater> _logger;

    /// <summary>Grace period before shutting down, so the caller receives its reply first.</summary>
    private static readonly TimeSpan ReplyGrace = TimeSpan.FromSeconds(3);

    public SelfUpdater(
        ISignatureInspector signatures,
        WinDiagOptions options,
        IHostApplicationLifetime lifetime,
        ILogger<SelfUpdater> logger)
    {
        _signatures = signatures;
        _options = options;
        _lifetime = lifetime;
        _logger = logger;
    }

    public SelfUpdateResult Update(string expectedSha256, string stagedFileName, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedSha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(stagedFileName);
        cancellationToken.ThrowIfCancellationRequested();

        var live = Environment.ProcessPath
                   ?? throw new SelfUpdateRejectedException("Cannot determine this server's own executable path.");

        var directory = Path.GetDirectoryName(live)!;

        // A file name, never a path: a caller must not be able to point this at an arbitrary location.
        if (Path.GetFileName(stagedFileName) != stagedFileName)
        {
            throw new SelfUpdateRejectedException(
                $"'{stagedFileName}' must be a file name, not a path. The staged build is only ever read " +
                "from the directory the server runs in.");
        }

        var staged = Path.Combine(directory, stagedFileName);
        if (!File.Exists(staged))
        {
            throw new SelfUpdateRejectedException(
                $"No staged build at '{staged}'. Copy the new executable there first.");
        }

        var inspection = _signatures.Inspect([staged], cancellationToken).Files.Single();

        var expected = expectedSha256.Trim().Replace("-", string.Empty);
        if (!string.Equals(inspection.Sha256, expected, StringComparison.OrdinalIgnoreCase))
        {
            // The check that matters most. A transfer to a target reached exactly the right size and was
            // corrupt, twice; only the hash caught it.
            throw new SelfUpdateRejectedException(
                $"The staged build does not match the hash you gave. Expected {expected}, found " +
                $"{inspection.Sha256}. Nothing has been changed. Re-send the file and try again.");
        }

        RequireSignatureRatchet(live, inspection, cancellationToken);

        var log = Path.Combine(_options.ArtifactDirectory, "self-update.log");
        Directory.CreateDirectory(_options.ArtifactDirectory);

        LaunchHelper(live, staged, inspection.Sha256, log);

        _logger.LogWarning(
            "self-update accepted ({Sha}); handing over to the helper and shutting down", inspection.Sha256);

        // Reply first, exit second: the caller needs the response before the socket dies, and the file
        // stays locked until this process is gone.
        _ = Task.Run(async () =>
        {
            await Task.Delay(ReplyGrace).ConfigureAwait(false);
            _lifetime.StopApplication();
        });

        return new SelfUpdateResult(
            StagedPath: staged,
            LivePath: live,
            SizeBytes: inspection.SizeBytes,
            Sha256: inspection.Sha256,
            SignatureVerdict: inspection.Verdict.ToString(),
            HelperLogPath: log,
            RestartScheduled: true);
    }

    /// <summary>
    /// A signed server refuses an unsigned or untrusted replacement.
    /// </summary>
    /// <remarks>
    /// Deliberately a ratchet rather than a setting. Unsigned development builds keep working, but once
    /// a target runs a signed build it cannot be downgraded to an unsigned one through this path — which
    /// is exactly the move an attacker with the token would want.
    /// </remarks>
    private void RequireSignatureRatchet(string live, FileSignature staged, CancellationToken cancellationToken)
    {
        var current = _signatures.Inspect([live], cancellationToken).Files.Single();

        if (current.Verdict != SignatureVerdict.Valid)
        {
            _logger.LogWarning(
                "the running build is unsigned, so the replacement's signature ({Verdict}) is not enforced",
                staged.Verdict);
            return;
        }

        if (staged.Verdict != SignatureVerdict.Valid)
        {
            throw new SelfUpdateRejectedException(
                $"This server is running a signed build, so it will only accept a signed replacement. " +
                $"The staged file is {staged.Verdict}: {staged.Detail} Nothing has been changed.");
        }
    }

    /// <summary>Writes and starts the helper that performs the swap once this process has exited.</summary>
    /// <remarks>
    /// The helper inherits this process's environment, so the relaunched server keeps its token without
    /// it ever being written to disk. It re-verifies the hash before moving, because the window between
    /// this check and the swap is one an attacker with file access could otherwise use.
    /// </remarks>
    private void LaunchHelper(string live, string staged, string sha256, string log)
    {
        var helper = Path.Combine(_options.ArtifactDirectory, "self-update.cmd");
        var arguments = string.Join(' ', Environment.GetCommandLineArgs().Skip(1).Select(Quote));

        var script = new StringBuilder()
            .AppendLine("@echo off")
            .AppendLine("setlocal enabledelayedexpansion")
            .AppendLine($">\"{log}\" echo [%date% %time%] self-update starting for PID {Environment.ProcessId}")
            .AppendLine(":waitforexit")
            .AppendLine($"tasklist /FI \"PID eq {Environment.ProcessId}\" 2>nul | find \"{Environment.ProcessId}\" >nul")
            .AppendLine("if not errorlevel 1 (timeout /t 1 /nobreak >nul & goto waitforexit)")
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
            .AppendLine($"  start \"windiag\" \"{live}\" {arguments}")
            .AppendLine("  exit /b 2")
            .AppendLine(")")
            .AppendLine($"move /y \"{staged}\" \"{live}\" >nul")
            .AppendLine("if errorlevel 1 (")
            .AppendLine($"  >>\"{log}\" echo [%time%] ABORT move failed; restarting the existing build")
            .AppendLine($"  start \"windiag\" \"{live}\" {arguments}")
            .AppendLine("  exit /b 3")
            .AppendLine(")")
            .AppendLine($">>\"{log}\" echo [%time%] swapped; relaunching")
            .AppendLine($"start \"windiag\" \"{live}\" {arguments}")
            .AppendLine($">>\"{log}\" echo [%time%] done")
            .ToString();

        File.WriteAllText(helper, script, Encoding.ASCII);

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

    private static string Quote(string argument) =>
        argument.Contains(' ', StringComparison.Ordinal) ? $"\"{argument}\"" : argument;
}
