namespace MacDiag.Mcp.Diagnostics.Processes;

/// <summary>One process as one pair of ps calls saw it.</summary>
/// <param name="StartTimeText">lstart as ps printed it: what an identity check compares, never the parsed form.</param>
/// <param name="ExecutablePath">comm when it is a full path; null when ps gave a bare name or the process had exited.</param>
public sealed record ProcessRecord(
    int ProcessId, int ParentProcessId, string Name, string State, DateTimeOffset? StartTime, string StartTimeText,
    long ResidentBytes, long? UserId, string? ExecutablePath, string? CommandLine);

/// <param name="Limitations">What the listing could not say, so a missing field is never read as an absent one.</param>
public sealed record ProcessTable(IReadOnlyList<ProcessRecord> Processes, IReadOnlyList<string> Limitations);

public interface IProcessTable
{
    Task<ProcessTable> ReadAsync(CancellationToken cancellationToken);
}

public sealed class ProcessQueryException : Exception, IDiagnosticException
{
    public ProcessQueryException(string message)
        : base(message)
    {
    }

    public ProcessQueryException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
