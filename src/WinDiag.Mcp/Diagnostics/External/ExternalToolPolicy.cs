using System.Text;

namespace WinDiag.Mcp.Diagnostics.External;

/// <summary>How one external tool must be invoked, and how to read what it writes.</summary>
/// <param name="StandardArguments">
/// Arguments prepended to every invocation of that tool.
/// </param>
/// <param name="Timeout">
/// Overrides the configured global budget. Needed for a tool whose normal runtime is measured in
/// minutes rather than seconds.
/// </param>
/// <param name="OutputEncoding">
/// How to decode the tool's stdout. Null means the console default. Set it only when a tool writes
/// something else, which is not discoverable from its help text.
/// </param>
/// <remarks>
/// This exists because none of these is universal, which is easy to assume and expensive to get wrong.
/// <para>Console Sysinternals tools take <c>-accepteula -nobanner</c>; Procmon does not recognise
/// <c>-nobanner</c> at all, and rejects it by showing a message box. Launched with
/// <c>CreateNoWindow</c> that dialog is invisible, so the mistake presents as a hang to the full
/// timeout rather than a non-zero exit.</para>
/// <para>And <c>autorunsc -c</c> writes <strong>UTF-16 LE with a BOM</strong>, where every other tool
/// here writes console text. Decoded as UTF-8 that arrives as text interleaved with NUL bytes, so the
/// header match fails and the parser reports a layout it does not recognise — which reads as a
/// Sysinternals version change rather than an encoding mistake.</para>
/// </remarks>
public sealed record ExternalToolPolicy(
    IReadOnlyList<string> StandardArguments,
    TimeSpan? Timeout = null,
    Encoding? OutputEncoding = null)
{
    /// <summary>Console tools: accept the EULA and suppress the banner, which would corrupt CSV output.</summary>
    public static readonly ExternalToolPolicy ConsoleTool = new(["-accepteula", "-nobanner"]);

    /// <summary>A console tool that writes UTF-16, which so far means autorunsc.</summary>
    public static readonly ExternalToolPolicy UnicodeConsoleTool =
        ConsoleTool with { OutputEncoding = Encoding.Unicode };

    /// <summary>
    /// A windowed tool: accept the EULA, and nothing else — an unrecognised switch would surface as an
    /// invisible dialog.
    /// </summary>
    public static ExternalToolPolicy Windowed(TimeSpan timeout) => new(["/AcceptEula"], timeout);
}
