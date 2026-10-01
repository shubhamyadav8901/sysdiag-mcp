namespace MacDiag.Mcp.Diagnostics.Log;

/// <param name="Level">The shared vocabulary: Critical, Error, Warning, Information or Verbose.</param>
/// <param name="MessageType">The unified log's own type -- Fault, Error, Default, Info, Debug -- so a Default shown as Warning names itself.</param>
/// <param name="Provider">The process that logged it.</param>
public sealed record EventEntry(
    DateTimeOffset TimeCreated, string Level, string MessageType, string Provider, string? Subsystem, string? Category, string? Message,
    int? ProcessId);

/// <param name="Truncated">More matched than were returned. Never set because a window could not be read in full; Limitations say that.</param>
public sealed record EventQueryResult(int Minutes, IReadOnlyList<EventEntry> Events, bool Truncated, IReadOnlyList<string> Limitations);

public interface ILogInspector
{
    Task<EventQueryResult> QueryAsync(
        string? process, string? subsystem, string? category, string? sender, int minutes, string[]? levels, int maxEvents,
        CancellationToken cancellationToken);
}

public sealed class LogQueryException : Exception, IDiagnosticException
{
    public LogQueryException(string message)
        : base(message)
    {
    }

    public LogQueryException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
