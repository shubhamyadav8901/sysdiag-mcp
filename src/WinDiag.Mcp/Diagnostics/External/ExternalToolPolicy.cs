namespace WinDiag.Mcp.Diagnostics.External;

/// <summary>How one external tool must be invoked.</summary>
/// <param name="StandardArguments">
/// Arguments prepended to every invocation of that tool.
/// </param>
/// <param name="Timeout">
/// Overrides the configured global budget. Needed for a tool whose normal runtime is measured in
/// minutes rather than seconds.
/// </param>
/// <remarks>
/// This exists because the standard prefix is <em>not</em> universal, which is easy to assume and
/// expensive to get wrong. Console Sysinternals tools take <c>-accepteula -nobanner</c>; Procmon does
/// not recognise <c>-nobanner</c> at all, and rejects it by showing a message box. Launched with
/// <c>CreateNoWindow</c> that dialog is invisible, so the mistake presents as a hang to the full
/// timeout rather than a non-zero exit.
/// </remarks>
public sealed record ExternalToolPolicy(IReadOnlyList<string> StandardArguments, TimeSpan? Timeout = null)
{
    /// <summary>Console tools: accept the EULA and suppress the banner, which would corrupt CSV output.</summary>
    public static readonly ExternalToolPolicy ConsoleTool = new(["-accepteula", "-nobanner"]);

    /// <summary>
    /// A windowed tool: accept the EULA, and nothing else — an unrecognised switch would surface as an
    /// invisible dialog.
    /// </summary>
    public static ExternalToolPolicy Windowed(TimeSpan timeout) => new(["/AcceptEula"], timeout);
}
