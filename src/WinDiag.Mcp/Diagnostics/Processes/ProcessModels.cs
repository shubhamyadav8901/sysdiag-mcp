namespace WinDiag.Mcp.Diagnostics.Processes;

/// <summary>One running process.</summary>
/// <param name="CommandLine">
/// Null when the command line could not be read, which unelevated means any process owned by another
/// user. Absence here is a permissions artefact, never evidence that a process was started bare.
/// </param>
public sealed record ProcessInfo(
    int ProcessId,
    int? ParentProcessId,
    string Name,
    DateTimeOffset? StartTime,
    long WorkingSetBytes,
    int ThreadCount,
    int? SessionId,
    string? ExecutablePath,
    string? CommandLine);

/// <summary>Result of a process listing.</summary>
/// <param name="CommandLinesRedacted">
/// How many processes matched but had an unreadable command line. Reported so a listing full of nulls
/// reads as "I could not see these" rather than "these have no arguments".
/// </param>
public sealed record ProcessListResult(
    IReadOnlyList<ProcessInfo> Processes,
    int TotalMatched,
    bool Truncated,
    int CommandLinesRedacted,
    string? Limitation);

/// <summary>Enumerates running processes.</summary>
public interface IProcessInspector
{
    ProcessListResult List(string? nameFilter, int? processId, CancellationToken cancellationToken);
}
