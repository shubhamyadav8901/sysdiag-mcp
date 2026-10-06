using System.Diagnostics;
using Diag.Mcp.Server.SelfUpdate;
using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Hosting;
using Microsoft.Extensions.Logging;

namespace LinuxDiag.Mcp.Diagnostics.SelfUpdate;

/// <summary>Swaps the staged build in once this process has exited, from outside the service's cgroup.</summary>
/// <remarks>
/// <para>The helper cannot simply be a detached child. Every process a service starts lives in that
/// service's cgroup, and systemd kills the whole cgroup when the service stops -- so a child would die
/// the moment this server exits, before it had swapped anything. systemd-run starts it as its own
/// transient unit instead, which outlives the service it was launched from.</para>
/// <para>Outside systemd -- a server started by hand -- there is no cgroup to escape, and setsid is
/// enough.</para>
/// </remarks>
public sealed class SystemdRestartHelper(LinuxDiagOptions options, ILogger<SystemdRestartHelper> logger) : IRestartHelper
{
    private const UnixFileMode OwnerOnlyExecutable = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    /// <summary>Why the artifact directory is not this server's alone; empty when it is.</summary>
    internal Func<string, IReadOnlyList<string>> DirectoryProblems { get; init; } =
        directory => TrustedDirectory.Problems(directory, TrustedDirectory.ThisProcess);

    public void Launch(string livePath, string stagedPath, string sha256, string logPath)
    {
        var pid = Environment.ProcessId;
        // One answer to "under systemd", used for both how the helper starts and how it restarts us.
        var underSystemd = UnderSystemd(options.ServiceName, Environment.GetEnvironmentVariable("INVOCATION_ID"));
        var restart = RestartCommand(underSystemd, options.ServiceName, livePath, Environment.GetCommandLineArgs().Skip(1).ToList());
        var script = Path.Combine(options.ArtifactDirectory, "self-update.sh");
        var body = Script(pid, livePath, stagedPath, sha256, logPath, restart);

        Directory.CreateDirectory(options.ArtifactDirectory, OwnerOnlyExecutable);

        // Checked here as well as at install: a later chmod, or LINUXDIAG_ARTIFACT_DIR pointed somewhere else,
        // would otherwise let another account swap the script between its creation and sh reading it.
        if (DirectoryProblems(options.ArtifactDirectory) is { Count: > 0 } problems)
        {
            throw new SelfUpdateRejectedException(
                $"Refusing to update: the helper script would be written to {options.ArtifactDirectory} and run as this " +
                $"server's account, and another account could change it there. {string.Join(" ", problems)} Make the " +
                "directory and those above it writable by this server's account alone. Nothing has been changed.");
        }

        File.Delete(script);
        using (var stream = new FileStream(script, new FileStreamOptions
               {
                   Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
                   UnixCreateMode = OwnerOnlyExecutable
               }))
        using (var writer = new StreamWriter(stream))
        {
            writer.Write(body);
        }

        var start = underSystemd
            ? new ProcessStartInfo("systemd-run") { ArgumentList = { "--collect", "--quiet", $"--unit={options.ServiceName}-update-{pid}", "/bin/sh", script } }
            : new ProcessStartInfo("setsid") { ArgumentList = { "/bin/sh", script } };
        start.UseShellExecute = false;

        using var process = Process.Start(start)
                            ?? throw new SelfUpdateRejectedException($"Could not start {start.FileName}. Nothing has been changed.");

        // systemd-run returns as soon as the unit is started; a failure here means no helper exists.
        if (underSystemd)
        {
            process.WaitForExit();
            if (process.ExitCode != 0)
            {
                throw new SelfUpdateRejectedException(
                    $"systemd-run refused to start the update helper (exit {process.ExitCode}). Nothing has been changed.");
            }
        }

        logger.LogInformation("self-update helper started ({How}), logging to {Log}", underSystemd ? "systemd-run" : "setsid", logPath);
    }

    /// <summary>True only when systemd started this process as the named service.</summary>
    /// <remarks>
    /// Both halves: the service name comes from the env file, but a by-hand run can inherit it too, and
    /// only systemd sets INVOCATION_ID. Restarting through systemctl from a by-hand run would restart the
    /// installed service instead of bringing this process back.
    /// </remarks>
    internal static bool UnderSystemd(string? serviceName, string? invocationId) =>
        !string.IsNullOrWhiteSpace(serviceName) && invocationId is not null;

    internal static string RestartCommand(bool underSystemd, string? serviceName, string live, IReadOnlyList<string> args) =>
        underSystemd && !string.IsNullOrWhiteSpace(serviceName)
            ? $"systemctl restart {ShellQuote(serviceName)}"
            : $"setsid {ShellQuote(live)} {string.Join(' ', args.Select(ShellQuote))} >/dev/null 2>&1 &";

    /// <summary>Single-quotes a value for sh, refusing one that contains a quote.</summary>
    /// <remarks>
    /// Refused rather than escaped: every path here is one this server chose, so a quote in one means
    /// something is wrong, and refusing leaves the running server untouched.
    /// </remarks>
    internal static string ShellQuote(string value) =>
        value.Contains('\'', StringComparison.Ordinal)
            ? throw new SelfUpdateRejectedException($"'{value}' contains a single quote, which the update helper cannot carry safely. Nothing has been changed.")
            : $"'{value}'";

    internal static string Script(int pid, string live, string staged, string sha256, string log, string restartCommand) => $"""
        #!/bin/sh
        # Written by linuxdiag update_self. Runs outside the service's cgroup (see SystemdRestartHelper).
        log={ShellQuote(log)}
        echo "[$(date -u +%FT%TZ)] self-update starting for PID {pid}" > "$log"
        while kill -0 {pid} 2>/dev/null; do sleep 1; done
        echo "[$(date -u +%FT%TZ)] server exited; re-verifying" >> "$log"
        actual=$(sha256sum {ShellQuote(staged)} | cut -d' ' -f1 | tr 'a-f' 'A-F')
        if [ "$actual" != {ShellQuote(sha256)} ]; then
          echo "[$(date -u +%FT%TZ)] ABORT hash mismatch: $actual; restarting the existing build" >> "$log"
          {restartCommand}
          exit 2
        fi
        if ! mv -f {ShellQuote(staged)} {ShellQuote(live)}; then
          echo "[$(date -u +%FT%TZ)] ABORT move failed; restarting the existing build" >> "$log"
          {restartCommand}
          exit 3
        fi
        chmod 0755 {ShellQuote(live)}
        echo "[$(date -u +%FT%TZ)] swapped; restarting" >> "$log"
        {restartCommand}
        echo "[$(date -u +%FT%TZ)] done" >> "$log"

        """;
}
