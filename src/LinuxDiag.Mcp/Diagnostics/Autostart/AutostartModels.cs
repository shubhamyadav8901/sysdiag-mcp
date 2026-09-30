namespace LinuxDiag.Mcp.Diagnostics.Autostart;

/// <param name="Profile">The account a per-user entry belongs to; null for system entries.</param>
/// <param name="ImagePath">The program that runs.</param>
/// <param name="ScriptPath">The script an interpreter runs, when the program is one.</param>
/// <param name="DropIns">Drop-ins that change a unit: a packaged unit can be overridden by one of these.</param>
/// <param name="Package">The package that owns the program, when packages were checked.</param>
/// <param name="Packaged">True when every file that decides what runs matches its package; null when not checked.</param>
/// <param name="PackageFindings">Each file that is not from a package, or was changed after it was installed.</param>
/// <param name="ImageMissing">The program does not exist: a leftover hook, or a hijack waiting for its file.</param>
public sealed record AutostartEntry(
    string Category, string Location, string Entry, bool Enabled, string? Profile, string? Description, string? ImagePath,
    string? LaunchString, string? ScriptPath, IReadOnlyList<string> DropIns, string? Package, bool? Packaged,
    IReadOnlyList<string> PackageFindings, bool ImageMissing);

public sealed record AutostartQuery(
    string Categories = "all", string? NameFilter = null, bool VerifyPackages = false, bool UnpackagedOnly = false,
    bool HidePackaged = false);

public sealed record AutostartAuditResult(
    IReadOnlyList<AutostartEntry> Entries, int TotalMatched, bool Truncated, bool Elevated, bool PackagesVerified,
    int UnpackagedCount, int MissingImageCount, IReadOnlyList<string> Limitations);

public interface IAutostartInspector
{
    Task<AutostartAuditResult> AuditAsync(AutostartQuery query, CancellationToken cancellationToken);
}
