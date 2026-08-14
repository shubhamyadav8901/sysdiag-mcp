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

/// <summary>Raised when an action on a process is refused or fails.</summary>
public sealed class ProcessControlException : Exception
{
    public ProcessControlException(string message) : base(message)
    {
    }

    public ProcessControlException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
