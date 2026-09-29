namespace WinDiag.Mcp.Diagnostics.EventLogs;

/// <summary>Severity filter for an event log query, in Windows' own ordering.</summary>
public enum EventLevel
{
    /// <summary>
    /// Level 0. Providers that define no level log here, and Event Viewer displays these as
    /// "Information".
    /// </summary>
    /// <remarks>
    /// Easy to omit and expensive to omit. Filtering on <c>Level=4</c> alone silently drops every
    /// level-0 record -- Event Viewer's own Information filter is <c>(Level=4 or Level=0)</c> -- and
    /// the tool then reports "no matching records", which reads as a quiet system rather than a
    /// mis-specified query.
    /// </remarks>
    LogAlways = 0,

    Critical = 1,
    Error = 2,
    Warning = 3,
    Information = 4,
    Verbose = 5
}

/// <summary>One record from a Windows event log.</summary>
public sealed record EventEntry(
    DateTimeOffset TimeCreated,
    int EventId,
    string Level,
    string Provider,
    string? Message,
    int? ProcessId);

/// <summary>Result of an event log query.</summary>
/// <param name="Candidates">
/// Available log names, offered when the requested log does not exist. Windows has hundreds of logs
/// with easily-mistyped names, so an empty result is far more often a wrong name than a quiet system.
/// </param>
public sealed record EventQueryResult(
    string Log,
    int Minutes,
    IReadOnlyList<EventEntry> Events,
    bool Truncated,
    IReadOnlyList<string> Candidates);

/// <summary>Reads recent records from the Windows event log.</summary>
public interface IEventLogInspector
{
    EventQueryResult Query(
        string log,
        int minutes,
        IReadOnlyList<EventLevel> levels,
        string? provider,
        IReadOnlyList<int> eventIds,
        int maxEvents,
        CancellationToken cancellationToken);
}

/// <summary>Raised when an event log query cannot be performed.</summary>
public sealed class EventLogQueryException : Exception, IDiagnosticException
{
    public EventLogQueryException(string message) : base(message)
    {
    }

    public EventLogQueryException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
