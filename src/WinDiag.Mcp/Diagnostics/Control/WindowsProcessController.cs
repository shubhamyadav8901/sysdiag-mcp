using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;

namespace WinDiag.Mcp.Diagnostics.Control;

/// <inheritdoc />
[SupportedOSPlatform("windows")]
public sealed class WindowsProcessController : IProcessController
{
    /// <summary>Processes that must never be touched, whatever the caller asks; see <see cref="ProtectedTargets"/>.</summary>
    private static readonly IReadOnlySet<string> Untouchable = ProtectedTargets.CoreProcesses;

    /// <summary>
    /// How far a live process's start time may differ from the caller's before it is treated as reused.
    /// </summary>
    private static readonly TimeSpan StartTimeTolerance = TimeSpan.FromSeconds(2);

    private readonly ILogger<WindowsProcessController> _logger;
    private readonly IProcessProtectionProbe _protection;

    public WindowsProcessController(ILogger<WindowsProcessController> logger, IProcessProtectionProbe protection)
    {
        _logger = logger;
        _protection = protection;
    }

    public ProcessControlResult Control(
        int processId,
        string expectedName,
        ProcessAction action,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedName);
        cancellationToken.ThrowIfCancellationRequested();

        // Refuse before opening. PID 4 cannot be opened for query at all, so leaving this check until
        // after Open() means the caller gets "access denied" instead of being told they just asked to
        // bugcheck the machine — a far less useful answer to a far more serious request.
        if (processId is 0 or 4 || Untouchable.Contains(Normalise(expectedName)))
        {
            throw new ProcessControlException(
                $"Refusing to {action.ToString().ToLowerInvariant()} PID {processId} ('{expectedName}'). " +
                "It is a core Windows process, and acting on it would take this machine down or log the " +
                "session out. Nothing has been done.");
        }

        if (processId == Environment.ProcessId)
        {
            throw new ProcessControlException(
                "Refusing to act on this diagnostics server's own process. Stopping it would end the " +
                "session that asked, and nothing would be left to report the result.");
        }

        using var process = Open(processId);
        var actualName = SafeName(process);

        // The identity check, before anything irreversible. A PID alone is not an identity: PIDs are
        // recycled, and a caller acting on one read from an earlier listing may be pointing at an
        // entirely different process by now.
        if (!NamesMatch(actualName, expectedName))
        {
            throw new ProcessControlException(
                $"PID {processId} is '{actualName}', not '{expectedName}'. Nothing has been done. " +
                "PIDs are reused, so this one probably belongs to a different process now - call " +
                "process_list to get a current one.");
        }

        // Checked again against the REAL name, not just the caller's claim, so naming a core process
        // as something innocuous does not get past the early refusal above.
        if (Untouchable.Contains(Normalise(actualName)))
        {
            throw new ProcessControlException(
                $"Refusing to {action.ToString().ToLowerInvariant()} '{actualName}' (PID {processId}). " +
                "It is a core Windows process, and acting on it would take this machine down or log the " +
                "session out. Nothing has been done.");
        }

        // Resume is never refused: it is how a frozen host is thawed, and refusing it would turn a mistake
        // the caller can undo into one nobody can.
        if (action != ProcessAction.Resume)
        {
            RequireUnprotected(process, actualName, processId, action);
        }

        var startTime = SafeStartTime(process);
        var detail = Act(process, action, actualName, processId);

        _logger.LogWarning("{Action} {Name} (PID {Pid})", action, actualName, processId);

        return new ProcessControlResult(processId, actualName, startTime, action, detail);
    }

    /// <summary>Refuses a process whose name is harmless but whose role is not.</summary>
    /// <remarks>
    /// <para>The name list above cannot see these. Every svchost is called svchost, and the one hosting
    /// DcomLaunch is a critical process -- ending it bugchecks the machine with CRITICAL_PROCESS_DIED -- while
    /// the ones hosting RpcSs or Winmgmt take RPC and WMI with them, and with those process_list and the
    /// service tools. service_control already refused to stop those services; ending their host by PID did
    /// the same thing without asking it. So the host is refused for whatever service_control refuses, and for
    /// anything Windows itself has marked critical.</para>
    /// <para>Fails closed: a process whose services or critical flag cannot be read is refused, because "could
    /// not tell" is not "safe".</para>
    /// </remarks>
    private void RequireUnprotected(Process process, string name, int processId, ProcessAction action)
    {
        var verb = action.ToString().ToLowerInvariant();

        IReadOnlyList<string> hosted;
        try
        {
            hosted = _protection.ServicesHostedBy(processId);
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            throw new ProcessControlException(
                $"Refusing to {verb} '{name}' (PID {processId}): could not list the services it hosts " +
                $"({ex.Message}), so whether it hosts one the machine needs is unknown. Nothing has been done.", ex);
        }

        var critical = hosted.Where(ProtectedTargets.CriticalServices.Contains).ToList();
        if (critical.Count > 0)
        {
            throw new ProcessControlException(
                $"Refusing to {verb} '{name}' (PID {processId}): it hosts {string.Join(", ", critical)}, which " +
                "service_control also refuses to stop. Ending or freezing the host stops them with it, and " +
                "without them RPC, WMI or the whole machine goes down. Nothing has been done.");
        }

        bool isCritical;
        try
        {
            isCritical = _protection.IsCritical(process);
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            throw new ProcessControlException(
                $"Refusing to {verb} '{name}' (PID {processId}): could not read whether Windows marks it " +
                $"critical ({ex.Message}). Nothing has been done.", ex);
        }

        if (isCritical)
        {
            throw new ProcessControlException(
                $"Refusing to {verb} '{name}' (PID {processId}): Windows marks it a critical process, and " +
                "ending one bugchecks the machine (CRITICAL_PROCESS_DIED). Nothing has been done.");
        }
    }

    private string Act(Process process, ProcessAction action, string name, int processId)
    {
        try
        {
            switch (action)
            {
                case ProcessAction.Terminate:
                    process.Kill(entireProcessTree: false);
                    process.WaitForExit(10_000);
                    return process.HasExited
                        ? "Terminated."
                        : "Kill was issued but the process has not exited yet; it may be stuck in the kernel.";

                case ProcessAction.Suspend:
                    Check(NtSuspendProcess(process.Handle), "suspend");
                    return "Suspended. Every thread is frozen; the process still exists and holds its " +
                           "handles and memory. Resume it when you are done, or it stays that way.";

                case ProcessAction.Resume:
                    Check(NtResumeProcess(process.Handle), "resume");
                    return "Resumed.";

                default:
                    throw new ProcessControlException($"'{action}' is not a supported action.");
            }
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or NotSupportedException)
        {
            throw new ProcessControlException(
                $"Could not {action.ToString().ToLowerInvariant()} '{name}' (PID {processId}): {ex.Message}. " +
                "Protected processes such as anti-malware services refuse this even when elevated.", ex);
        }
    }

    private static void Check(int status, string what)
    {
        if (status != 0)
        {
            throw new ProcessControlException($"Failed to {what} the process (NTSTATUS 0x{status:X8}).");
        }
    }

    private static Process Open(int processId)
    {
        try
        {
            var process = Process.GetProcessById(processId);
            _ = process.Handle;
            return process;
        }
        catch (ArgumentException ex)
        {
            throw new ProcessControlException(
                $"No process with PID {processId} is running. Nothing has been done.", ex);
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            throw new ProcessControlException(
                $"Could not open PID {processId}: {ex.Message}. Elevation is the usual cause when the " +
                "target belongs to another user.", ex);
        }
    }

    /// <summary>Compares image names, tolerating the .exe suffix in either position.</summary>
    internal static bool NamesMatch(string actual, string expected) =>
        string.Equals(Normalise(actual), Normalise(expected), StringComparison.OrdinalIgnoreCase);

    private static string Normalise(string value) =>
        Path.GetFileNameWithoutExtension(value.Trim()).Trim();

    /// <summary>True when a live process's start time is too far from the caller's to be the same one.</summary>
    /// <remarks>Internal so the recycling rule is testable without contriving real PID reuse.</remarks>
    internal static bool IsPidReused(DateTimeOffset? expectedStart, DateTimeOffset actualStart) =>
        expectedStart is { } expected && (actualStart - expected).Duration() > StartTimeTolerance;

    private static string SafeName(Process process)
    {
        try
        {
            return process.ProcessName;
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
            return "(unreadable)";
        }
    }

    private static DateTimeOffset? SafeStartTime(Process process)
    {
        try
        {
            return new DateTimeOffset(process.StartTime);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
            return null;
        }
    }

    [DllImport("ntdll.dll")]
    private static extern int NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll")]
    private static extern int NtResumeProcess(IntPtr processHandle);
}
