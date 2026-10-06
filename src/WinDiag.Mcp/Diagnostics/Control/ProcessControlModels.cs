namespace WinDiag.Mcp.Diagnostics.Control;

/// <summary>What to do to a process.</summary>
public enum ProcessAction
{
    /// <summary>End it. Irreversible, and it loses whatever the process had not written out.</summary>
    Terminate,

    /// <summary>Freeze every thread. Useful for catching a hang in the act; the process stays alive.</summary>
    Suspend,

    /// <summary>Unfreeze a suspended process.</summary>
    Resume
}

/// <summary>Outcome of acting on a process.</summary>
public sealed record ProcessControlResult(
    int ProcessId,
    string ProcessName,
    DateTimeOffset? StartTime,
    ProcessAction Action,
    string Detail);

/// <summary>Terminates, suspends and resumes processes.</summary>
public interface IProcessController
{
    /// <param name="expectedName">
    /// The image name the caller believes that PID belongs to. Verified before anything happens.
    /// </param>
    ProcessControlResult Control(
        int processId,
        string expectedName,
        ProcessAction action,
        CancellationToken cancellationToken);
}

/// <summary>What Windows knows about a process that its name does not say.</summary>
/// <remarks>
/// Behind an interface so a test can hand the controller a svchost that hosts RpcSs, or a process marked
/// critical, without finding a real one to risk.
/// </remarks>
public interface IProcessProtectionProbe
{
    /// <summary>Short names of the running services this process hosts; empty for one that hosts none.</summary>
    /// <exception cref="System.ComponentModel.Win32Exception">The service list could not be read.</exception>
    IReadOnlyList<string> ServicesHostedBy(int processId);

    /// <summary>True when Windows bugchecks the machine if this process exits.</summary>
    /// <exception cref="System.ComponentModel.Win32Exception">The flag could not be read.</exception>
    bool IsCritical(System.Diagnostics.Process process);
}

/// <summary>Raised when an action on a process is refused or fails.</summary>
public sealed class ProcessControlException : Exception, IDiagnosticException
{
    public ProcessControlException(string message) : base(message)
    {
    }

    public ProcessControlException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
