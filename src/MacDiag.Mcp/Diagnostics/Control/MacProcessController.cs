using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Mac.Launchd;
using MacDiag.Mcp.Mac.Parsers;
using Microsoft.Extensions.Logging;

namespace MacDiag.Mcp.Diagnostics.Control;

/// <summary>Signals a process after checking it is the one the caller means, through /bin/kill.</summary>
/// <remarks>
/// <para>macOS has no pidfd, so a PID cannot be pinned between the check and the signal. The identity -- name and
/// start time -- is read, checked, and read again immediately before kill; what remains is a window of milliseconds,
/// stated in every result rather than hidden.</para>
/// <para>/bin/kill rather than kill(2) by P/Invoke: the race is identical, and it keeps the native surface at plan 1's
/// open, write and close. It also sidesteps signal numbers, which differ from Linux (SIGSTOP is 17 here).</para>
/// <para>Protection is by the last segment of comm -- the executable -- never argv[0], which sshd rewrites and any
/// process can set to anything.</para>
/// </remarks>
public sealed partial class MacProcessController(IExternalCommand commands, MacDiagOptions options, ILogger<MacProcessController> logger)
    : IProcessController
{
    /// <summary>Processes refused by name: launchd itself, the kernel, logins, the display, logging, directory services, remote access.</summary>
    /// <remarks>On-demand remote-access daemons have no main PID in launchctl list, so they are named here.</remarks>
    internal static readonly HashSet<string> ProtectedNames = new(StringComparer.Ordinal)
    {
        "launchd", "kernel_task", "sshd", "sshd-session", "loginwindow", "WindowServer", "logd", "opendirectoryd", "screensharingd", "ARDAgent",
    };

    internal const string WindowNote =
        "macOS has no pidfd: between the last check and the signal there is a window of milliseconds in which the PID could be reused.";

    private static readonly TimeSpan StartTimeTolerance = TimeSpan.FromSeconds(1);

    /// <summary>macOS gives people uids from 501 up; below are system accounts.</summary>
    private const int FirstUserId = 501;
    private readonly LaunchdProtection _protection = new(options);

    internal TimeSpan ExitWait { get; init; } = TimeSpan.FromSeconds(10);

    internal TimeSpan PollDelay { get; init; } = TimeSpan.FromMilliseconds(250);

    internal Func<int> SelfPid { get; init; } = static () => Environment.ProcessId;

    internal Func<bool> IsRoot { get; init; } = static () => Environment.IsPrivilegedProcess;

    public async Task<ProcessControlResult> ControlAsync(
        int processId, string expectedName, ProcessAction action, DateTimeOffset? expectedStartTime, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(processId);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedName);
        var expected = expectedName.Trim();
        if (expected.EndsWith('/'))
        {
            throw new ArgumentException($"'{expectedName}' is a directory, not a process name.", nameof(expectedName));
        }

        if (processId == 1)
        {
            throw new ProcessControlException("PID 1 is launchd; signalling it would take down the whole Mac. Nothing was sent.");
        }

        if (processId == SelfPid())
        {
            throw new ProcessControlException("That PID is this server itself; use update_self to restart it. Nothing was sent.");
        }

        var identity = await IdentityAsync(processId, cancellationToken).ConfigureAwait(false)
                       ?? throw new ProcessControlException($"No process with PID {processId} is running. Call process_list for a current one; PIDs are reused.");
        var name = LastSegment(identity.Comm);
        if (identity.Stat.Contains('Z', StringComparison.Ordinal))
        {
            throw new ProcessControlException($"PID {processId} ({name}) is a zombie: it has already exited and only waits for its parent. Nothing was sent.");
        }

        if (!NamesMatch(identity.Comm, identity.ArgvZero, expected))
        {
            throw new ProcessControlException(
                $"PID {processId} is not '{expected}': it runs {identity.Comm} (argv[0] '{identity.ArgvZero}'). Nothing was sent.");
        }

        // Measured on macOS 26: waitid(P_ALL, WEXITED | WNOHANG | WNOWAIT) also reports a *stopped* child, which POSIX
        // says it must not. .NET's SIGCHLD handler asks exactly that, finds the child not exited, and asks again -- at
        // 100% CPU, holding the lock every Process start and dispose needs. The server would hang on its next ps and
        // never send the SIGCONT that frees it. Only a direct child raises SIGCHLD here, so only it is refused.
        if (action == ProcessAction.Suspend && identity.ParentId == SelfPid())
        {
            throw new ProcessControlException(
                $"PID {processId} is a child of this server, and stopping its own child would hang the server: .NET's child " +
                "watcher on macOS then spins forever and every later command - resume included - waits behind it. Nothing was sent.");
        }

        if (action != ProcessAction.Resume)
        {
            await RequireUnprotectedAsync(processId, name, identity.ArgvZero, cancellationToken).ConfigureAwait(false);
        }

        if (expectedStartTime is { } wanted && (identity.Start is not { } started || (started - wanted).Duration() > StartTimeTolerance))
        {
            throw new ProcessControlException(
                $"PID {processId} started at {identity.StartText}, not at the expected time: the PID has been reused. Nothing was sent.");
        }

        // The last look before the signal: a PID that changed hands since the checks above is refused.
        var again = await CommAsync(processId, cancellationToken).ConfigureAwait(false);
        if (again is null || again.StartText != identity.StartText || again.Command != identity.Comm)
        {
            throw new ProcessControlException($"PID {processId} changed hands while it was being checked. Nothing was sent.");
        }

        var detail = await SignalAsync(processId, name, action, identity.Stat, cancellationToken).ConfigureAwait(false);
        return new ProcessControlResult(processId, name, identity.Start, action, $"{detail} {WindowNote}");
    }

    /// <summary>A plain name matches the executable's file name or argv[0]'s; a path matches the executable or argv[0] exactly.</summary>
    internal static bool NamesMatch(string comm, string? argvZero, string expected) =>
        expected.Contains('/', StringComparison.Ordinal)
            ? (comm.StartsWith('/') && comm == expected) || argvZero == expected
            : LastSegment(comm) == expected || (argvZero is not null && LastSegment(argvZero) == expected);

    private async Task RequireUnprotectedAsync(int processId, string name, string? argvZero, CancellationToken cancellationToken)
    {
        // The executable decides; argv[0] ("sshd: admin [priv]") is also checked, because macOS's comm may follow it --
        // refusing on either can only refuse more.
        var argvName = argvZero is null ? null : LastSegment(argvZero).TrimEnd(':');
        if (ProtectedNames.Contains(name) || (argvName is not null && ProtectedNames.Contains(argvName)))
        {
            throw new ProcessControlException(
                $"PID {processId} is {(ProtectedNames.Contains(name) ? name : argvName)}, which this Mac needs to stay usable or reachable. Nothing was sent.");
        }

        // Fail closed: if the protected jobs cannot be listed, a protected daemon's PID cannot be told apart.
        var list = await commands.RunAsync("launchctl", ["list"], options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        if (list.ExitCode != 0)
        {
            throw new ProcessControlException(
                $"The list of protected launchd jobs could not be read ({list.StandardError.Trim()}), so only resume is allowed. Nothing was sent.");
        }

        // A list with no jobs in it is not "nothing protected"; it is a list that could not be read.
        var jobs = LaunchctlList.Parse(list.StandardOutput);
        if (jobs.Count == 0)
        {
            throw new ProcessControlException("launchctl list returned no jobs, so protected processes cannot be told apart; only resume is allowed. Nothing was sent.");
        }

        // Run as root, launchctl list is the system domain; run as anyone else inside a user session, it is that user's
        // own domain. The shipped server is a root LaunchDaemon, so the second case is a server started by hand.
        var root = IsRoot();
        Func<string, string?> refusal = root ? _protection.Refusal : _protection.RefusalInUserDomain;
        if (jobs.FirstOrDefault(row => row.ProcessId == processId && refusal(row.Label) is not null)
            is { Label: { Length: > 0 } label })
        {
            throw new ProcessControlException($"PID {processId} is the main process of the protected launchd job '{label}'. Nothing was sent.");
        }

        if (root)
        {
            await RequireUnprotectedInUserDomainAsync(processId, jobs, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>A human account's process may be the main process of a job in that user's own domain -- a remote-access
    /// agent such as Tailscale's or TeamViewer's -- which root's launchctl list does not show.</summary>
    /// <remarks>
    /// <para>launchctl asuser alone changes the bootstrap but not the credentials, and root's launchctl may then still
    /// answer for the system domain; so the list is run as the user too (sudo -n -u #uid, which root may do without a
    /// password), in the user's bootstrap, where it prints the same documented table for the user's own domain.</para>
    /// <para>Accounts below 501, and nobody (-2), are system accounts with no user session and so no agents; asking
    /// for one would refuse every signal to _www and its kin. A user's list that cannot be read, that is empty -- a
    /// session always holds Apple's agents -- or that is the system list again fails closed. That includes a user
    /// who has logged out but left processes behind: only resume is allowed for them until they log in.</para>
    /// <para><b>Unverified on a Mac</b>: the capture script records this list, and CI's macOS job settles it.</para>
    /// </remarks>
    private async Task RequireUnprotectedInUserDomainAsync(
        int processId, IReadOnlyList<(int? ProcessId, string Status, string Label)> systemJobs, CancellationToken cancellationToken)
    {
        var pid = processId.ToString(CultureInfo.InvariantCulture);
        var owner = await commands.RunAsync("ps", ["-p", pid, "-o", "uid="], options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        if (owner.ExitCode != 0 || !long.TryParse(owner.StandardOutput.Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var uid))
        {
            throw new ProcessControlException($"PID {processId}'s owner could not be read, so its user's protected jobs cannot be checked; only resume is allowed. Nothing was sent.");
        }

        // nobody prints as -2 or as 4294967294, its unsigned spelling.
        if (uid < FirstUserId || uid > int.MaxValue)
        {
            return;
        }

        var account = uid.ToString(CultureInfo.InvariantCulture);
        var list = await commands.RunAsync("launchctl", ["asuser", account, "sudo", "-n", "-u", $"#{account}", "launchctl", "list"], options.ExternalToolTimeout, cancellationToken)
            .ConfigureAwait(false);
        if (list.ExitCode != 0)
        {
            throw new ProcessControlException(
                $"The launchd jobs of uid {uid}, who owns PID {processId}, could not be read ({list.StandardError.Trim()}), so only resume is allowed. Nothing was sent.");
        }

        var jobs = LaunchctlList.Parse(list.StandardOutput);
        if (jobs.Count == 0)
        {
            throw new ProcessControlException(
                $"The launchd list for uid {uid}, who owns PID {processId}, was empty, which no user session is; only resume is allowed. Nothing was sent.");
        }

        if (jobs.Select(j => j.Label).ToHashSet(StringComparer.Ordinal).SetEquals(systemJobs.Select(j => j.Label)))
        {
            throw new ProcessControlException(
                $"Asking for uid {uid}'s launchd jobs returned the system domain's instead, so its agents cannot be told apart; only resume is allowed. Nothing was sent.");
        }

        if (jobs.FirstOrDefault(row => row.ProcessId == processId && _protection.RefusalInUserDomain(row.Label) is not null)
            is { Label: { Length: > 0 } label })
        {
            throw new ProcessControlException($"PID {processId} is the main process of '{label}', a protected job in uid {uid}'s own launchd domain. Nothing was sent.");
        }
    }

    private async Task<string> SignalAsync(int processId, string name, ProcessAction action, string stat, CancellationToken cancellationToken)
    {
        var signal = action switch
        {
            ProcessAction.Terminate => "TERM",
            ProcessAction.Kill => "KILL",
            ProcessAction.Suspend => "STOP",
            _ => "CONT",
        };
        await KillAsync(processId, signal, cancellationToken).ConfigureAwait(false);
        logger.LogWarning("process_control: sent {Signal} to {Name} (PID {ProcessId})", signal, name, processId);

        if (action == ProcessAction.Terminate && stat.Contains('T', StringComparison.Ordinal))
        {
            // A stopped process cannot act on SIGTERM until it runs again; it may have exited already, which is fine.
            await KillAsync(processId, "CONT", cancellationToken, toleratesGone: true).ConfigureAwait(false);
        }

        return action switch
        {
            ProcessAction.Suspend => "Suspended (SIGSTOP). Remember to resume it - a process left stopped is indistinguishable from one that is hung.",
            ProcessAction.Resume => "Resumed (SIGCONT).",
            _ => await ExitedAsync(processId, cancellationToken).ConfigureAwait(false)
                ? "Exited."
                : action == ProcessAction.Terminate
                    ? $"Sent SIGTERM; it has not exited after {ExitWait.TotalSeconds:0} s. Use action 'kill' if it must go."
                    : $"Sent SIGKILL; it has not exited after {ExitWait.TotalSeconds:0} s - it may be in uninterruptible I/O (state U).",
        };
    }

    private async Task KillAsync(int processId, string signal, CancellationToken cancellationToken, bool toleratesGone = false)
    {
        var result = await commands.RunAsync("kill", ["-s", signal, processId.ToString(CultureInfo.InvariantCulture)], options.ExternalToolTimeout, cancellationToken)
            .ConfigureAwait(false);
        if (result.ExitCode == 0)
        {
            return;
        }

        var error = result.StandardError.Trim();
        if (error.Contains("No such process", StringComparison.Ordinal))
        {
            if (toleratesGone)
            {
                return;
            }

            throw new ProcessControlException($"PID {processId} exited before it could be signalled.");
        }

        throw new ProcessControlException(error.Contains("Operation not permitted", StringComparison.Ordinal)
            ? $"Signalling PID {processId} needs root: it belongs to another user."
            : $"kill -s {signal} {processId} failed: {error}");
    }

    private async Task<bool> ExitedAsync(int processId, CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        do
        {
            var stat = await commands.RunAsync("ps", ["-p", processId.ToString(CultureInfo.InvariantCulture), "-o", "stat="], options.ExternalToolTimeout, cancellationToken)
                .ConfigureAwait(false);
            if (stat.ExitCode != 0 || stat.StandardOutput.Trim().Length == 0 || stat.StandardOutput.Contains('Z', StringComparison.Ordinal))
            {
                return true;
            }

            await Task.Delay(PollDelay, cancellationToken).ConfigureAwait(false);
        }
        while (watch.Elapsed < ExitWait);

        return false;
    }

    private sealed record Identity(int ParentId, string Stat, string StartText, DateTimeOffset? Start, string Comm, string? ArgvZero);

    private async Task<Identity?> IdentityAsync(int processId, CancellationToken cancellationToken)
    {
        var pid = processId.ToString(CultureInfo.InvariantCulture);
        var line = await commands.RunAsync("ps", ["-p", pid, "-ww", "-o", "pid=,ppid=,stat=,lstart=,comm="], options.ExternalToolTimeout, cancellationToken)
            .ConfigureAwait(false);
        if (line.ExitCode != 0 || IdentityLine().Match(line.StandardOutput.Trim()) is not { Success: true } match)
        {
            return null;
        }

        var args = await commands.RunAsync("ps", ["-p", pid, "-ww", "-o", "args="], options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        var argvZero = args.ExitCode == 0 ? VisDecode.Decode(args.StandardOutput.Trim()).Split(' ', 2)[0] : null;
        var startText = Spaces().Replace(match.Groups[4].Value, " ");
        DateTimeOffset? start = DateTime.TryParseExact(startText, "ddd MMM d HH:mm:ss yyyy", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var parsed)
            ? new DateTimeOffset(parsed)
            : null;
        return new Identity(
            int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture),
            match.Groups[3].Value,
            startText,
            start,
            VisDecode.Decode(match.Groups[5].Value),
            string.IsNullOrEmpty(argvZero) ? null : argvZero);
    }

    private async Task<PsCommRow?> CommAsync(int processId, CancellationToken cancellationToken)
    {
        var result = await commands.RunAsync(
            "ps", ["-p", processId.ToString(CultureInfo.InvariantCulture), "-ww", "-o", "pid=,lstart=,comm="], options.ExternalToolTimeout, cancellationToken)
            .ConfigureAwait(false);
        return result.ExitCode == 0 ? PsTable.ParseComm(result.StandardOutput).Commands.GetValueOrDefault(processId) : null;
    }

    private static string LastSegment(string path) => path[(path.TrimEnd('/').LastIndexOf('/') + 1)..];

    [GeneratedRegex(@"^(\d+)\s+(\d+)\s+(\S+)\s+([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+)$")]
    private static partial Regex IdentityLine();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Spaces();
}
