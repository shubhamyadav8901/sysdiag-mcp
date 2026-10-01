namespace MacDiag.Mcp.Diagnostics.Control;

/// <summary>What process_control does: terminate is SIGTERM and a wait, kill is SIGKILL, suspend and resume are SIGSTOP and SIGCONT.</summary>
public enum ProcessAction
{
    Terminate,
    Kill,
    Suspend,
    Resume,
}

public sealed record ProcessControlResult(int ProcessId, string ProcessName, DateTimeOffset? StartTime, ProcessAction Action, string Detail);

public interface IProcessController
{
    Task<ProcessControlResult> ControlAsync(
        int processId, string expectedName, ProcessAction action, DateTimeOffset? expectedStartTime, CancellationToken cancellationToken);
}

public sealed class ProcessControlException : Exception, IDiagnosticException
{
    public ProcessControlException(string message)
        : base(message)
    {
    }

    public ProcessControlException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
