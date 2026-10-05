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
/// <para>SIGHUP is ignored with trap rather than nohup. Under the system launchd domain the helper never ran -- the
/// server exited, nothing was swapped and nothing restarted it (CI's install smoke) -- while the same line worked in a
/// login session; macOS's nohup also tries to detach from a console session, which a daemon has none of. The helper's
/// stderr goes to its log, so a helper that cannot start leaves a reason there instead of in /dev/null.</para>
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

        // The script's and the log's paths travel as $0 and $1, never spliced into the command text.
        var start = new ProcessStartInfo("/bin/sh") { UseShellExecute = false };
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add("trap '' HUP; set -m; /bin/sh \"$0\" </dev/null >/dev/null 2>>\"$1\" &");
        start.ArgumentList.Add(script);
        start.ArgumentList.Add(logPath);
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
    /// <param name="tools">Where each program is; the system's by default. A seam so a test can run the script with fakes.</param>
    /// <param name="confirmSeconds">How long the new build has to come up before it is rolled back.</param>
    internal static string Script(
        int pid, string live, string staged, string sha256, string log, string? label, (string Host, int Port)? probe,
        IReadOnlyList<string> args, HelperTools? tools = null, int confirmSeconds = 30)
    {
        // Every program by its absolute path: a root helper started from a by-hand `sudo -E` run inherits the
        // caller's PATH, and must no more take programs from /usr/local than the runner does.
        var t = tools ?? HelperTools.System;
        var l = ShellQuote(live);
        var s = ShellQuote(staged);
        var old = ShellQuote(live + ".old");
        var job = label is null ? null : ShellQuote("system/" + label);
        // SIGHUP stays ignored from the launch line, so the relaunched server inherits that without nohup.
        var relaunch = $"{l} {string.Join(' ', args.Select(ShellQuote))} </dev/null >/dev/null 2>&1 &".Replace("  <", " <", StringComparison.Ordinal);
        var startOld = job is null ? relaunch : $"{t.Launchctl} kickstart {job}";
        var startNew = job is null ? relaunch : $"{t.Launchctl} kickstart -k {job}";
        var newPid = job is null
            ? "  newpid=new"
            : $"  newpid=$({t.Launchctl} print {job} 2>/dev/null | {t.Sed} -n 's/^[[:space:]]*pid = \\([0-9]*\\)$/\\1/p' | {t.Head} -n 1)";
        var answers = probe is { } p ? $"  {t.Nc} -z -G 2 {ShellQuote(p.Host)} {p.Port} >/dev/null 2>&1 || continue" : "  :";
        var hashOf = (string file) => $"{t.Shasum} -a 256 {file} | {t.Cut} -d' ' -f1 | {t.Tr} 'a-f' 'A-F'";

        return $"""
            #!/bin/sh
            # Written by macdiag update_self. Detached from the daemon; see LaunchdRestartHelper.
            log={ShellQuote(log)}
            stamp() {"{"} {t.Date} -u +%Y-%m-%dT%H:%M:%SZ; {"}"}
            echo "[$(stamp)] self-update starting for PID {pid}" > "$log"
            while kill -0 {pid} 2>/dev/null; do {t.Sleep} 1; done
            echo "[$(stamp)] server exited; re-verifying" >> "$log"
            actual=$({hashOf(s)})
            if [ "$actual" != {ShellQuote(sha256)} ]; then
              echo "[$(stamp)] ABORT hash mismatch: $actual; starting the existing build" >> "$log"
              {startOld}
              exit 2
            fi
            if ! {t.Ln} -f {l} {old}; then
              echo "[$(stamp)] ABORT backup failed; starting the existing build" >> "$log"
              {startOld}
              exit 3
            fi
            if ! {t.Mv} -f {s} {l}; then
              echo "[$(stamp)] ABORT move failed; starting the existing build" >> "$log"
              {startOld}
              exit 4
            fi
            {t.Chmod} 0755 {l}
            echo "[$(stamp)] swapped; starting the new build" >> "$log"
            {startNew}
            ok=0
            i=0
            while [ $i -lt {confirmSeconds} ]; do
              {t.Sleep} 1
              i=$((i + 1))
            {newPid}
              [ -n "$newpid" ] && [ "$newpid" != {pid} ] || continue
              now=$({hashOf(l)})
              [ "$now" = {ShellQuote(sha256)} ] || continue
            {answers}
              ok=1
              break
            done
            if [ $ok -ne 1 ]; then
              echo "[$(stamp)] ROLLBACK the new build did not come up; restoring the previous one" >> "$log"
              {t.Mv} -f {old} {l}
              {startNew}
              exit 5
            fi
            echo "[$(stamp)] done" >> "$log"

            """.ReplaceLineEndings("\n");
    }
}

/// <summary>The absolute path of every program the update helper runs.</summary>
internal sealed record HelperTools(
    string Shasum, string Launchctl, string Nc, string Ln, string Mv, string Chmod, string Sed, string Head, string Cut,
    string Tr, string Sleep, string Date)
{
    /// <summary>Where macOS keeps them; all in the runner's system directories.</summary>
    public static readonly HelperTools System = new(
        "/usr/bin/shasum", "/bin/launchctl", "/usr/bin/nc", "/bin/ln", "/bin/mv", "/bin/chmod", "/usr/bin/sed",
        "/usr/bin/head", "/usr/bin/cut", "/usr/bin/tr", "/bin/sleep", "/bin/date");
}
