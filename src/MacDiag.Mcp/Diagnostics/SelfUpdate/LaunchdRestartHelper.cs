using System.Diagnostics;
using Diag.Mcp.Server.SelfUpdate;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Hosting;
using Microsoft.Extensions.Logging;

namespace MacDiag.Mcp.Diagnostics.SelfUpdate;

/// <summary>Swaps the staged build in once this process has exited, then brings the server back through launchd.</summary>
/// <remarks>
/// <para>The helper is a detached shell in its own process group. When the daemon stops, launchd would kill the whole
/// group; the plist's AbandonProcessGroup is what lets the helper outlive it. set -m is a best effort on top.</para>
/// <para>The server exits 0 for an update, and KeepAlive restarts only a failed exit, so nothing brings it back but
/// this script: every branch that gives up starts the existing build again before it exits.</para>
/// </remarks>
public sealed class LaunchdRestartHelper(MacDiagOptions options, ILogger<LaunchdRestartHelper> logger) : IRestartHelper
{
    private const UnixFileMode OwnerOnlyExecutable = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    public void Launch(string livePath, string stagedPath, string sha256, string logPath)
    {
        var underLaunchd = LaunchdJob.IsOurs(options.ServiceLabel);
        var probe = options.HttpBind is { } bind ? MacServiceInstaller.ProbeAddress(bind) : ((string, int)?)null;
        var body = Script(Environment.ProcessId, livePath, stagedPath, sha256, logPath, underLaunchd ? options.ServiceLabel : null,
            probe, Environment.GetCommandLineArgs().Skip(1).ToList());

        var script = Path.Combine(options.ArtifactDirectory, "self-update.sh");
        Directory.CreateDirectory(options.ArtifactDirectory, OwnerOnlyExecutable);
        File.Delete(script);
        using (var stream = new FileStream(script, new FileStreamOptions
               {
                   Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, UnixCreateMode = OwnerOnlyExecutable,
               }))
        using (var writer = new StreamWriter(stream))
        {
            writer.Write(body);
        }

        // The script's path travels as $0, never spliced into the command text.
        var start = new ProcessStartInfo("/bin/sh") { UseShellExecute = false };
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add("set -m; nohup /bin/sh \"$0\" >/dev/null 2>&1 &");
        start.ArgumentList.Add(script);
        using var process = Process.Start(start)
                            ?? throw new SelfUpdateRejectedException("Could not start /bin/sh for the update helper. Nothing has been changed.");
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new SelfUpdateRejectedException($"The update helper did not start (exit {process.ExitCode}). Nothing has been changed.");
        }

        logger.LogInformation("self-update helper started ({How}), logging to {Log}", underLaunchd ? "launchd" : "relaunch", logPath);
    }

    /// <summary>Single-quotes a value for sh, refusing one that contains a quote.</summary>
    /// <remarks>Refused rather than escaped: every value here is one this server chose, so a quote means something is wrong.</remarks>
    internal static string ShellQuote(string value) =>
        value.Contains('\'', StringComparison.Ordinal)
            ? throw new SelfUpdateRejectedException($"'{value}' contains a single quote, which the update helper cannot carry safely. Nothing has been changed.")
            : $"'{value}'";

    /// <param name="label">The launchd label when the server is its own job; null when it was started by hand.</param>
    /// <param name="probe">Where the server listens, to confirm it answers; null in stdio mode.</param>
    internal static string Script(
        int pid, string live, string staged, string sha256, string log, string? label, (string Host, int Port)? probe, IReadOnlyList<string> args)
    {
        var l = ShellQuote(live);
        var s = ShellQuote(staged);
        var old = ShellQuote(live + ".old");
        var job = label is null ? null : ShellQuote("system/" + label);
        var relaunch = $"nohup {l} {string.Join(' ', args.Select(ShellQuote))} >/dev/null 2>&1 &".Replace("  >", " >", StringComparison.Ordinal);
        var startOld = job is null ? relaunch : $"launchctl kickstart {job}";
        var startNew = job is null ? relaunch : $"launchctl kickstart -k {job}";
        var newPid = job is null
            ? "  newpid=new"
            : $"  newpid=$(launchctl print {job} 2>/dev/null | sed -n 's/^[[:space:]]*pid = \\([0-9]*\\)$/\\1/p' | head -n 1)";
        var answers = probe is { } p ? $"  nc -z -G 2 {ShellQuote(p.Host)} {p.Port} >/dev/null 2>&1 || continue" : "  :";

        return $"""
            #!/bin/sh
            # Written by macdiag update_self. Detached from the daemon; see LaunchdRestartHelper.
            log={ShellQuote(log)}
            stamp() {"{"} date -u +%Y-%m-%dT%H:%M:%SZ; {"}"}
            echo "[$(stamp)] self-update starting for PID {pid}" > "$log"
            while kill -0 {pid} 2>/dev/null; do sleep 1; done
            echo "[$(stamp)] server exited; re-verifying" >> "$log"
            actual=$(shasum -a 256 {s} | cut -d' ' -f1 | tr 'a-f' 'A-F')
            if [ "$actual" != {ShellQuote(sha256)} ]; then
              echo "[$(stamp)] ABORT hash mismatch: $actual; starting the existing build" >> "$log"
              {startOld}
              exit 2
            fi
            if ! ln -f {l} {old}; then
              echo "[$(stamp)] ABORT backup failed; starting the existing build" >> "$log"
              {startOld}
              exit 3
            fi
            if ! mv -f {s} {l}; then
              echo "[$(stamp)] ABORT move failed; starting the existing build" >> "$log"
              {startOld}
              exit 4
            fi
            chmod 0755 {l}
            echo "[$(stamp)] swapped; starting the new build" >> "$log"
            {startNew}
            ok=0
            i=0
            while [ $i -lt 30 ]; do
              sleep 1
              i=$((i + 1))
            {newPid}
              [ -n "$newpid" ] && [ "$newpid" != {pid} ] || continue
              now=$(shasum -a 256 {l} | cut -d' ' -f1 | tr 'a-f' 'A-F')
              [ "$now" = {ShellQuote(sha256)} ] || continue
            {answers}
              ok=1
              break
            done
            if [ $ok -ne 1 ]; then
              echo "[$(stamp)] ROLLBACK the new build did not come up; restoring the previous one" >> "$log"
              mv -f {old} {l}
              {startNew}
              exit 5
            fi
            echo "[$(stamp)] done" >> "$log"

            """.ReplaceLineEndings("\n");
    }
}
