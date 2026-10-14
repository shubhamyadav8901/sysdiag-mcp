namespace WinDiag.Mcp.Diagnostics.Autostart;

/// <summary>One thing configured to run without anybody starting it.</summary>
/// <param name="Category">Autoruns' own grouping: Logon, Services, Scheduled Tasks, Explorer, and so on.</param>
/// <param name="Location">Where it is configured — a registry key, or "Task Scheduler".</param>
/// <param name="Entry">The value or task name within that location.</param>
/// <param name="Enabled">False for an entry that is present but switched off.</param>
/// <param name="ImagePath">
/// The file that would run. Null when Autoruns reported none at all.
/// </param>
/// <param name="ImageMissing">
/// True when the entry names a file that is not there. Autoruns reports this by writing
/// <c>File not found: &lt;path&gt;</c> into the image column rather than by leaving it empty, so
/// without splitting it out the field is prose that no path comparison matches and no filter finds —
/// and the entry renders more quietly than a healthy one, which is backwards. An autostart hook
/// pointing at nothing is the classic shape of an uninstalled product that did not clean up.
/// </param>
/// <param name="SignatureVerdict">Null unless signature verification was requested.</param>
/// <param name="Timestamp">
/// When the entry was last written, in UTC. Autoruns is asked for normalised UTC explicitly, because
/// its default is a locale-formatted local time that cannot be parsed portably.
/// </param>
/// <param name="Profile">
/// Whose autostart this is: <c>System-wide</c>, or the account (<c>DOMAIN\user</c>) whose profile holds
/// it. Every profile is scanned, so two users' identical HKCU Run values differ only here.
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
    DateTimeOffset? Timestamp,
    bool ImageMissing = false);

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
/// False means the profiles of users who are logged off and some protected keys were not readable, so
/// an absent entry does not mean it is not configured. Every profile is always asked for; elevation is
/// what lets autorunsc load the ones not already loaded.
/// </param>
/// <param name="MalformedRowCount">
/// Rows of autorunsc's output that could not be read as a whole entry and are not in
/// <see cref="Entries"/>. Non-zero means the list is incomplete, and possibly that a hostile value name
/// was trying to hide or forge an entry.
/// </param>
public sealed record AutostartAuditResult(
    IReadOnlyList<AutostartEntry> Entries,
    int TotalMatched,
    bool Truncated,
    bool Elevated,
    bool SignaturesVerified,
    int UnsignedCount,
    int MissingImageCount = 0,
    int MalformedRowCount = 0);

/// <summary>Lists what is configured to start on its own.</summary>
public interface IAutostartInspector
{
    Task<AutostartAuditResult> AuditAsync(AutostartQuery query, CancellationToken cancellationToken);
}
