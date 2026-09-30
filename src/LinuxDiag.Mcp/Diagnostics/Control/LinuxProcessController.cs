using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Linux.Native;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Linux.Proc;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;

namespace LinuxDiag.Mcp.Diagnostics.Control;

public sealed partial class LinuxProcessController(ILogger<LinuxProcessController> logger) : IProcessController
{
    /// <summary>How long terminate and kill wait to see the process exit. A test shortens it.</summary>
    internal TimeSpan ExitWait { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>How far a start time may differ from the expected one and still be the same process.</summary>
    /// <remarks>Both come from the same boot time and clock ticks, so they agree exactly; a second covers rounding.</remarks>
    private static readonly TimeSpan StartTimeTolerance = TimeSpan.FromSeconds(1);

    public ProcessControlResult Control(
        int processId, string expectedName, ProcessAction action, CancellationToken cancellationToken,
        DateTimeOffset? expectedStartTime = null)
    {
        if (processId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(processId), "A process id must be positive. Get one from process_list.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(expectedName);
        if (Path.GetFileName(expectedName.Trim()).Length == 0)
        {
            throw new ArgumentException("Give the process's name, for example 'nginx', not a directory.", nameof(expectedName));
        }

        if (processId == 1)
        {
            throw new ProcessControlException(
                "Refusing to signal PID 1, the init process: stopping it takes the machine down, and most signals to " +
                "it are ignored anyway. Nothing has been done.");
        }

        if (processId == Environment.ProcessId)
        {
            throw new ProcessControlException(
                "Refusing to act on this diagnostics server's own process. Stopping it would end the session that " +
                "asked, and nothing would be left to report the result.");
        }

        if (!LibC.Supported)
        {
            throw new ProcessControlException("process_control needs x86-64 Linux, where its syscalls and signal numbers are defined.");
        }

        using var pidfd = Open(processId);

        // Read after the pidfd is open. If the PID was reused in between, this reads the newcomer -- and the
        // signal below, sent through the pidfd, can only fail with ESRCH; it cannot reach the newcomer.
        var stat = ProcStat.Parse(ProcFiles.ReadProcess(processId, "stat")
            ?? throw new ProcessControlException($"PID {processId} exited before it could be checked. Nothing has been done."));
        if (stat.IsKernelThread)
        {
            throw new ProcessControlException(
                $"PID {processId} ({stat.Name}) is a kernel thread; signals to it are ignored or dangerous. Nothing has been done.");
        }

        var executable = Optional(() => ProcFiles.ReadProcessLink(processId, "exe"));
        var argv0 = Optional(() => ProcFiles.ReadProcess(processId, "cmdline"))?.Split('\0')[0];
        if (!NamesMatch(stat.Name, executable, argv0, expectedName))
        {
            throw new ProcessControlException(
                $"PID {processId} is '{stat.Name}', not '{expectedName}'. Nothing has been done. PIDs are reused, so " +
                "this one probably belongs to a different process now - call process_list to get a current one.");
        }

        if (stat.State == "Z")
        {
            throw new ProcessControlException(
                $"PID {processId} ({stat.Name}) has already exited and is a zombie waiting for its parent (PID " +
                $"{stat.ParentProcessId}) to reap it; signals do nothing to it. Nothing has been done.");
        }

        if (action != ProcessAction.Resume && IsProtected(stat.Name, executable, stat.ParentProcessId))
        {
            throw new ProcessControlException(
                $"Refusing to {action.ToString().ToLowerInvariant()} '{stat.Name}' (PID {processId}): it is a daemon this machine " +
                "needs - logging, logins, devices, the system bus, networking or remote access - and stopping or freezing it " +
                "can cut the machine off, these diagnostics included. Nothing has been done.");
        }

        var started = KernelStat.BootTime(ProcFiles.Read(ProcFiles.KernelStat)) +
                      TimeSpan.FromSeconds(stat.StartTimeTicks / (double)LinuxProcessTable.ClockTicksPerSecond);

        // The pidfd pins the process only from this call on. A PID reused before the call by a process with
        // the same name -- another prefork worker, another sh -- passes the name check; its start time does not.
        if (expectedStartTime is { } expected && (started - expected).Duration() > StartTimeTolerance)
        {
            throw new ProcessControlException(
                $"PID {processId} ('{stat.Name}') started at {started:u}, not {expected:u}. Nothing has been done. " +
                "PIDs are reused, so this is a different process - call process_list to get a current one.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            LibC.SendSignal(pidfd, Signal(action));
        }
        catch (ErrnoException ex) when (ex.Errno == ErrnoException.ESRCH)
        {
            throw new ProcessControlException($"PID {processId} exited before it could be signalled. Nothing has been done.");
        }
        catch (ErrnoException ex) when (ex.Errno == ErrnoException.EPERM)
        {
            throw new ProcessControlException(
                $"Could not {action.ToString().ToLowerInvariant()} '{stat.Name}' (PID {processId}): permission denied. " +
                "Signalling another user's process needs root.");
        }

        // Logged the moment it is sent: a root signal must leave an audit line even if the wait below fails.
        LogSent(logger, SignalName(action), stat.Name, processId);

        // SIGTERM stays pending on a stopped process until it runs again, so a suspended process is continued
        // after it -- as systemd does -- or terminate would always wait out its timeout. Its own try: SIGTERM has
        // been delivered by now, so a failure here must not say "nothing has been done".
        if (action == ProcessAction.Terminate && stat.State == "T")
        {
            try
            {
                LibC.SendSignal(pidfd, LibC.SIGCONT);
            }
            catch (ErrnoException ex) when (ex.Errno == ErrnoException.ESRCH)
            {
                // It exited on SIGTERM already.
            }
            catch (ErrnoException ex)
            {
                throw new ProcessControlException(
                    $"SIGTERM was sent to '{stat.Name}' (PID {processId}), but continuing it with SIGCONT failed: {ex.Message}. " +
                    "It stays suspended with SIGTERM pending; resume it to let it act on the signal.", ex);
            }
        }

        string detail;
        try
        {
            detail = action switch
            {
                ProcessAction.Suspend => "Stopped with SIGSTOP. Every thread is frozen until it is resumed, so it can be inspected in the meantime.",
                ProcessAction.Resume => "Continued with SIGCONT.",
                _ => AfterStop(pidfd, processId, action, cancellationToken),
            };
        }
        catch (Exception ex) when (ex is OperationCanceledException or ErrnoException or IOException or FormatException)
        {
            throw new ProcessControlException(
                $"{SignalName(action)} was sent to '{stat.Name}' (PID {processId}), but waiting to see it exit " +
                $"{(ex is OperationCanceledException ? "was cancelled" : "failed: " + ex.Message)}. Call process_list " +
                "to see whether it is still running.", ex);
        }

        if (StateNote(stat.State, action) is { } note)
        {
            detail += " " + note;
        }

        LogControlled(logger, action, stat.Name, processId, detail);
        return new ProcessControlResult(processId, stat.Name, started, action, detail);
    }

    /// <summary>Whether the name the caller expects is this process's: its comm, its executable, or argv[0].</summary>
    /// <remarks>
    /// Exactly, as Linux names are: case-sensitive, and a path compared whole, never by its last part -- a
    /// /tmp/nginx is not /usr/sbin/nginx. Only comm has a prefix rule, because only comm is cut to 15 bytes.
    /// </remarks>
    internal static bool NamesMatch(string comm, string? executable, string? argv0, string expected)
    {
        var wanted = expected.Trim();
        if (wanted.Contains('/', StringComparison.Ordinal))
        {
            return string.Equals(executable, wanted, StringComparison.Ordinal) || string.Equals(argv0, wanted, StringComparison.Ordinal);
        }

        return comm == wanted ||
               (comm.Length == 15 && wanted.Length > 15 && wanted.StartsWith(comm, StringComparison.Ordinal)) ||
               (executable is not null && Path.GetFileName(executable) == wanted) ||
               (argv0 is { Length: > 0 } && Path.GetFileName(argv0) == wanted);
    }

    /// <summary>Daemons whose stop or freeze cuts the machine off: the processes service_control also protects.</summary>
    private static readonly HashSet<string> ProtectedDaemons = new(StringComparer.Ordinal)
    {
        "systemd-journald", "systemd-logind", "systemd-udevd", "systemd-networkd", "systemd-resolved", "dbus-daemon",
        "dbus-broker", "NetworkManager", "polkitd", "sshd", "tailscaled", "openvpn",
    };

    /// <summary>One of those daemons itself -- a child of PID 1 -- not a login session's sshd or a udev worker.</summary>
    internal static bool IsProtected(string comm, string? executable, int parentProcessId) =>
        parentProcessId == 1 &&
        ((executable is not null && ProtectedDaemons.Contains(Path.GetFileName(executable))) ||
         ProtectedDaemons.Contains(comm) ||
         (comm.Length == 15 && ProtectedDaemons.Any(d => d.StartsWith(comm, StringComparison.Ordinal))));

    /// <summary>What a stopped process's state means for the signal just sent, or null when it changes nothing.</summary>
    internal static string? StateNote(string state, ProcessAction action) => (state, action) switch
    {
        ("t", ProcessAction.Terminate) =>
            "It is stopped under a debugger (tracing stop): SIGTERM stays pending until the debugger lets it run.",
        ("T", ProcessAction.Terminate) =>
            "It was suspended, so it was continued to act on SIGTERM - if it handles SIGTERM and keeps running, it is now running, not suspended.",
        _ => null,
    };

    private static SafeFileHandle Open(int processId)
    {
        try
        {
            return LibC.OpenPidFd(processId);
        }
        catch (ErrnoException ex)
        {
            throw ex.Errno switch
            {
                ErrnoException.ESRCH => new ProcessControlException($"No process with PID {processId} is running. Nothing has been done."),
                ErrnoException.EINVAL => new ProcessControlException(
                    $"PID {processId} is a thread of another process, not a process. Pass the process's PID - the Tgid " +
                    $"line of /proc/{processId}/status. Nothing has been done."),
                ErrnoException.EPERM => new ProcessControlException(
                    $"The kernel refused to open PID {processId} (EPERM): a seccomp filter or container profile blocks " +
                    "pidfd_open for this server, so it cannot signal safely here. Nothing has been done."),
                ErrnoException.ENOSYS => new ProcessControlException(
                    "This kernel has no pidfd_open (Linux 5.3 or later is needed), so a process cannot be signalled " +
                    "without the risk of hitting a reused PID. Nothing has been done."),
                _ => new ProcessControlException($"Could not open PID {processId}: {ex.Message}. Nothing has been done.", ex),
            };
        }
    }

    /// <summary>Another user's exe link or command line may be unreadable; the other names still count.</summary>
    private static string? Optional(Func<string?> read)
    {
        try
        {
            return read();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    private static string SignalName(ProcessAction action) => action switch
    {
        ProcessAction.Terminate => "SIGTERM",
        ProcessAction.Kill => "SIGKILL",
        ProcessAction.Suspend => "SIGSTOP",
        _ => "SIGCONT",
    };

    private static int Signal(ProcessAction action) => action switch
    {
        ProcessAction.Terminate => LibC.SIGTERM,
        ProcessAction.Kill => LibC.SIGKILL,
        ProcessAction.Suspend => LibC.SIGSTOP,
        _ => LibC.SIGCONT,
    };

    private string AfterStop(SafeFileHandle pidfd, int processId, ProcessAction action, CancellationToken cancellationToken)
    {
        if (LibC.WaitForExit(pidfd, ExitWait, cancellationToken))
        {
            // Exited -- but a zombie keeps its /proc entry until the parent reaps it, so say who that is.
            var after = ProcFiles.ReadProcess(processId, "stat") is { } text ? ProcStat.Parse(text) : null;
            return after is { State: "Z" }
                ? $"Exited. It remains a zombie until its parent (PID {after.ParentProcessId}) reaps it."
                : "Exited.";
        }

        return action == ProcessAction.Terminate
            ? $"Sent SIGTERM, but it has not exited after {ExitWait.TotalSeconds:0.#} s: it may be handling or ignoring " +
              "the signal. Use action 'kill' to end it outright."
            : "Sent SIGKILL, but it has not exited yet: it is probably in uninterruptible sleep (state D) inside the " +
              "kernel, and will die when that call returns.";
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "process_control: sent {Signal} to {Name} (PID {ProcessId})")]
    private static partial void LogSent(ILogger logger, string signal, string name, int processId);

    [LoggerMessage(Level = LogLevel.Warning, Message = "process_control: {Action} {Name} (PID {ProcessId}): {Detail}")]
    private static partial void LogControlled(ILogger logger, ProcessAction action, string name, int processId, string detail);
}
