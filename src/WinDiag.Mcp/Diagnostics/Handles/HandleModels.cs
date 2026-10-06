namespace WinDiag.Mcp.Diagnostics.Handles;

/// <summary>One open handle reported by <c>handle.exe -u -v</c>.</summary>
/// <remarks>
/// The field set mirrors what that flag combination actually emits. Notably it does <em>not</em>
/// include share flags or granted access, despite handle.exe printing both in its CSV header --
/// see <see cref="HandleCsvParser"/>.
/// </remarks>
/// <param name="Unproven">
/// The row came after an object name that can contain a line break, so it may be text from inside that
/// name rather than a row of its own. Its process is certain -- the parser lists such a row only under the
/// process that holds that object -- but its type, handle value and name are not.
/// </param>
public sealed record HandleEntry(
    string ProcessName,
    int ProcessId,
    string Type,
    string? User,
    string HandleValue,
    string Name,
    bool Unproven = false);

/// <summary>Result of an exhaustive handle search.</summary>
/// <param name="Elevated">
/// Whether the search ran elevated. handle.exe loads a kernel driver and, unelevated, returns a
/// partial list with scattered access-denied errors -- which reads exactly like a complete list with
/// fewer results. Carried explicitly so the rendering layer must account for it.
/// </param>
/// <param name="Truncated">True when more matches existed than the configured result cap.</param>
/// <param name="ProcessScoped">
/// True when the query named a PID rather than an object-name fragment. Carried because the advice
/// attached to an empty result differs: telling someone who passed a PID to "call again with a
/// broader search term" is instructions for a tool they did not use.
/// </param>
/// <param name="IncludedAllObjectTypes">
/// False means only file references were searched. Carried so an empty result can say which universe
/// it was empty over -- "no files matched" and "nothing of any kind matched" are different answers,
/// and conflating them sends the caller down the wrong path.
/// </param>
/// <param name="UnparsedRows">
/// Rows handle.exe printed that could not be attributed to one process -- a comma in an image name can
/// make a row ambiguous, since handle.exe quotes nothing, and after an object name that can hold a line
/// break a line claiming another process may be more of that name. Each may be a handle that exists and is not in
/// <see cref="Entries"/>, so a non-zero count forbids reading an empty list as "nothing holds it".
/// </param>
public sealed record HandleSearchResult(
    string Query,
    IReadOnlyList<HandleEntry> Entries,
    bool Elevated,
    bool Truncated,
    int TotalMatched,
    bool IncludedAllObjectTypes,
    bool ProcessScoped = false,
    int UnparsedRows = 0);
