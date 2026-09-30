namespace LinuxDiag.Mcp.Diagnostics.Journal;

/// <param name="Level">windiag's name for the priority: Critical, Error, Warning, Information or Verbose.</param>
/// <param name="Priority">The syslog priority, 0 (emerg) to 7 (debug).</param>
/// <param name="Provider">SYSLOG_IDENTIFIER, or the process's command name when there is none.</param>
public sealed record EventEntry(
    DateTimeOffset TimeCreated, string Level, int Priority, string Provider, string? Unit, string? Message, int? ProcessId);

public sealed record EventQueryResult(
    string? Unit, int Minutes, IReadOnlyList<EventEntry> Events, bool Truncated, IReadOnlyList<string> Candidates,
    IReadOnlyList<string> Limitations);

public interface IJournalInspector
{
    Task<EventQueryResult> QueryAsync(
        string? unit, int minutes, string[]? levels, string? provider, string[]? match, int maxEvents,
        CancellationToken cancellationToken);
}
