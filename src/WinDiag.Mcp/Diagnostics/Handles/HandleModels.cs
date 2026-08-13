namespace WinDiag.Mcp.Diagnostics.Handles;

/// <summary>One open handle reported by <c>handle.exe -u -v</c>.</summary>
/// <remarks>
/// The field set mirrors what that flag combination actually emits. Notably it does <em>not</em>
/// include share flags or granted access, despite handle.exe printing both in its CSV header --
/// see <see cref="HandleCsvParser"/>.
/// </remarks>
public sealed record HandleEntry(
    string ProcessName,
    int ProcessId,
    string Type,
    string? User,
    string HandleValue,
    string Name);

/// <summary>Result of an exhaustive handle search.</summary>
/// <param name="Elevated">
/// Whether the search ran elevated. handle.exe loads a kernel driver and, unelevated, returns a
/// partial list with scattered access-denied errors -- which reads exactly like a complete list with
/// fewer results. Carried explicitly so the rendering layer must account for it.
/// </param>
/// <param name="Truncated">True when more matches existed than the configured result cap.</param>
/// <param name="IncludedAllObjectTypes">
/// False means only file references were searched. Carried so an empty result can say which universe
/// it was empty over -- "no files matched" and "nothing of any kind matched" are different answers,
/// and conflating them sends the caller down the wrong path.
/// </param>
public sealed record HandleSearchResult(
    string Query,
    IReadOnlyList<HandleEntry> Entries,
    bool Elevated,
    bool Truncated,
    int TotalMatched,
    bool IncludedAllObjectTypes);
