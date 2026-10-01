namespace MacDiag.Mcp.Diagnostics.Autostart;

/// <param name="Location">The file that makes it start: a launchd plist, a crontab, a periodic script, a preferences file.</param>
/// <param name="Profile">The account a per-user entry belongs to, or a crontab line's user; null for system entries.</param>
/// <param name="Description">When it runs: launchd's triggers, or a cron schedule.</param>
/// <param name="ImagePath">The program that runs.</param>
/// <param name="ScriptPath">The script an interpreter runs, when the program is one.</param>
/// <param name="Signed">Whether the program's signature verifies; false for a script; null when not checked.</param>
/// <param name="ImageMissing">The program or its script does not exist: a leftover, or a hijack waiting for its file.</param>
/// <param name="WritableByOthers">Another account could change what runs: the file, the program, or a directory above either.</param>
/// <param name="Findings">Each reason behind WritableByOthers or ImageMissing, naming the path.</param>
public sealed record AutostartEntry(
    string Category, string Location, string Entry, bool Enabled, string? Profile, string? Description, string? ImagePath,
    string? LaunchString, string? ScriptPath, bool? Signed, string? SignatureDetail, bool ImageMissing, bool WritableByOthers,
    IReadOnlyList<string> Findings);

public sealed record AutostartQuery(
    string Categories = "all", string? NameFilter = null, bool HideApple = true, bool VerifySignatures = false, bool UnsignedOnly = false);

public sealed record AutostartAuditResult(
    IReadOnlyList<AutostartEntry> Entries, int TotalMatched, bool Truncated, bool Elevated, bool SignaturesVerified,
    int UnsignedCount, int MissingImageCount, int WritableByOthersCount, IReadOnlyList<string> Limitations);

public interface IAutostartInspector
{
    Task<AutostartAuditResult> AuditAsync(AutostartQuery query, CancellationToken cancellationToken);
}
