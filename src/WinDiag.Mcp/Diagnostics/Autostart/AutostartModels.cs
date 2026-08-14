namespace WinDiag.Mcp.Diagnostics.Autostart;

/// <summary>One thing configured to run without anybody starting it.</summary>
/// <param name="Category">Autoruns' own grouping: Logon, Services, Scheduled Tasks, Explorer, and so on.</param>
/// <param name="Location">Where it is configured — a registry key, or "Task Scheduler".</param>
/// <param name="Entry">The value or task name within that location.</param>
/// <param name="Enabled">False for an entry that is present but switched off.</param>
/// <param name="ImagePath">
/// The file that would run. Null when Autoruns could not resolve one, which is itself worth seeing:
/// an entry pointing at nothing is a leftover, and an entry Autoruns calls "File not found" is the
/// classic shape of an uninstalled product leaving a hook behind.
/// </param>
/// <param name="SignatureVerdict">Null unless signature verification was requested.</param>
/// <param name="Timestamp">
/// When the entry was last written, in UTC. Autoruns is asked for normalised UTC explicitly, because
/// its default is a locale-formatted local time that cannot be parsed portably.
/// </param>
public sealed record AutostartEntry(
    string Category,
    string Location,
    string Entry,
    bool Enabled,
    string? Profile,
    string? Description,
    string? Company,
    string? ImagePath,
    string? Version,
    string? LaunchString,
    string? SignatureVerdict,
    DateTimeOffset? Timestamp);

/// <summary>What to ask Autoruns for.</summary>
/// <param name="Categories">
/// Autoruns category letters, already validated. Never caller text: the tool takes friendly names and
/// maps them here, so nothing a caller types reaches the argument vector.
/// </param>
/// <param name="NameFilter">
/// Applied by this server after parsing, not by Autoruns — it has no such switch. That is a feature
/// rather than a workaround: it means <c>autostart_audit</c> composes an argument vector containing no
/// caller-supplied element at all.
/// </param>
public sealed record AutostartQuery(
    string Categories = "*",
    string? NameFilter = null,
    bool VerifySignatures = false,
    bool UnsignedOnly = false,
    bool HideMicrosoft = false);

/// <summary>Result of an autostart audit.</summary>
/// <param name="Elevated">
/// False means entries under other users' profiles and some protected keys were not readable, so an
/// absent entry does not mean it is not configured.
/// </param>
public sealed record AutostartAuditResult(
    IReadOnlyList<AutostartEntry> Entries,
    int TotalMatched,
    bool Truncated,
    bool Elevated,
    bool SignaturesVerified,
    int UnsignedCount);

/// <summary>Lists what is configured to start on its own.</summary>
public interface IAutostartInspector
{
    Task<AutostartAuditResult> AuditAsync(AutostartQuery query, CancellationToken cancellationToken);
}
