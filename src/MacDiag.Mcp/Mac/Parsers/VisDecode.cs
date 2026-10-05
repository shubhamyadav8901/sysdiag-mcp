namespace MacDiag.Mcp.Mac.Parsers;

/// <summary>Undoes the one part of macOS ps's escaping that can be undone: \011 for a tab and \012 for a newline.</summary>
/// <remarks>
/// <para>What ps prints, measured on macOS 26 with the UTF-8 LC_CTYPE the server gives it: valid UTF-8 byte for byte; a
/// tab or newline as \011 or \012; any other control as ^x with no backslash (^A, ^[, ^? for DEL); a byte that is not
/// part of a printable character either as itself or, from 0x80 to 0x9F, as M^@ to M^_. A backslash in a command line
/// is printed as-is, so a literal "a\011b" prints exactly as a real tab would.</para>
/// <para>Only the two backslash escapes are decoded. ^x and M-x carry no marker, and the text they look like is
/// common: a regex argument "^[a-z]" would become ESC. Under the UTF-8 locale an M- sequence that spells valid UTF-8
/// is never ps's own, since ps prints valid characters raw, so decoding one could only rewrite a real argument. A raw
/// invalid byte is already U+FFFD by the time the output is a string; nothing here can bring it back.</para>
/// <para>The cost of decoding \011 and \012 is a literal backslash-0-1-1 in an argument, which is rare; a newline in
/// an argument (sh -c, python -c, osascript -e) is not.</para>
/// </remarks>
public static class VisDecode
{
    public static string Decode(string printed)
    {
        ArgumentNullException.ThrowIfNull(printed);
        return printed.Contains('\\', StringComparison.Ordinal)
            ? printed.Replace("\\011", "\t", StringComparison.Ordinal).Replace("\\012", "\n", StringComparison.Ordinal)
            : printed;
    }
}
