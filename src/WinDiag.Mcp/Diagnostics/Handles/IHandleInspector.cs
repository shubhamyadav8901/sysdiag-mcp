namespace WinDiag.Mcp.Diagnostics.Handles;

/// <summary>Search for open handles by object name.</summary>
public interface IHandleInspector
{
    /// <summary>
    /// Finds handles whose object name contains <paramref name="nameFragment"/>, across all processes.
    /// </summary>
    /// <param name="includeAllObjectTypes">
    /// <para>False (default) searches <em>file references only</em>, which is what handle.exe does
    /// without <c>-a</c>. Fast enough for interactive use.</para>
    /// <para>True adds <c>-a</c> and covers every named kernel object -- registry keys, sections,
    /// mutants, events, tokens. Measured cost on an ordinary workstation: a machine-wide <c>-a</c>
    /// search had produced 223 rows and had not yet reached a single non-file object after 6m40s,
    /// against a 120s default budget. Expect it to need a narrow search term, a raised
    /// <c>WINDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS</c>, or both.</para>
    /// </param>
    Task<HandleSearchResult> SearchAsync(
        string nameFragment,
        bool includeAllObjectTypes,
        CancellationToken cancellationToken);
}
