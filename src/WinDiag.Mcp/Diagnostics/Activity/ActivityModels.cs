namespace WinDiag.Mcp.Diagnostics.Activity;

/// <summary>One traced file or registry operation.</summary>
public sealed record ActivityEvent(
    string Time,
    string ProcessName,
    int ProcessId,
    string Operation,
    string Path,
    string Result,
    string Detail);

/// <summary>A name and how many times it occurred.</summary>
public sealed record ActivityCount(string Name, int Count);

/// <summary>What a capture produced.</summary>
/// <param name="PmlPath">The native trace. Opens in the Procmon GUI unchanged, for a human to continue in.</param>
/// <param name="CsvPath">The exported form, which <c>query_activity</c> reads.</param>
public sealed record ActivityCapture(
    string PmlPath,
    string? PmlUncPath,
    string CsvPath,
    string? CsvUncPath,
    long PmlSizeBytes,
    long CsvSizeBytes,
    int DurationSeconds,
    int TotalEvents,
    IReadOnlyList<ActivityCount> ProblemResults,
    IReadOnlyList<ActivityCount> TopProcesses);

/// <summary>Result of querying a saved capture.</summary>
/// <param name="Scanned">Every event read, before filtering — the denominator for what follows.</param>
public sealed record ActivityQueryResult(
    string CapturePath,
    int Scanned,
    int Matched,
    bool Truncated,
    IReadOnlyList<ActivityEvent> Events,
    IReadOnlyList<ActivityCount> TopPaths,
    IReadOnlyList<ActivityCount> TopProcesses,
    IReadOnlyList<ActivityCount> Results);

/// <summary>Filters for a query over a saved capture.</summary>
public sealed record ActivityFilter(
    string? ProcessName = null,
    int? ProcessId = null,
    string? PathContains = null,
    string? Operation = null,
    bool ProblemsOnly = false,
    int MaxEvents = 100,
    // A substring of the Detail column, matched server-side. Detail is Procmon's operation-specific
    // text ("Desired Access: ..., Disposition: OverwriteIf, ShareMode: ..."), so this is how a predicate
    // that lives only in Detail -- Disposition, Desired Access, ShareMode -- gets pushed to the scan
    // instead of pulled back and filtered by the caller.
    string? DetailContains = null);

/// <summary>Captures file and registry activity, and queries what was captured.</summary>
public interface IActivityInspector
{
    Task<ActivityCapture> CaptureAsync(int durationSeconds, CancellationToken cancellationToken);

    ActivityQueryResult Query(string capturePath, ActivityFilter filter, CancellationToken cancellationToken);
}

/// <summary>Raised when a capture could not be performed.</summary>
public sealed class ActivityCaptureException : Exception, IDiagnosticException
{
    public ActivityCaptureException(string message) : base(message)
    {
    }

    public ActivityCaptureException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
