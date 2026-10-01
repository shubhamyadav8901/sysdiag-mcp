using System.Text;

namespace MacDiag.Mcp.Mac.Parsers;

/// <summary>Undoes vis(3) as BSD ps applies it to command lines: \M-x, \M^x and \^x, and nothing else.</summary>
/// <remarks>
/// The bytes the sequences name are collected and decoded as UTF-8, so a vis-encoded "café" reads as itself. A run
/// that is not valid UTF-8 is left exactly as ps printed it rather than turned into replacement characters.
/// </remarks>
public static class VisDecode
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static string Decode(string printed)
    {
        ArgumentNullException.ThrowIfNull(printed);
        if (!printed.Contains('\\', StringComparison.Ordinal))
        {
            return printed;
        }

        var bytes = new List<byte>(printed.Length);
        var i = 0;
        while (i < printed.Length)
        {
            if (printed[i] == '\\' && Sequence(printed, i) is { } decoded)
            {
                bytes.Add(decoded.Value);
                i += decoded.Length;
                continue;
            }

            bytes.AddRange(Encoding.UTF8.GetBytes(printed[i].ToString()));
            i++;
        }

        try
        {
            return StrictUtf8.GetString(bytes.ToArray());
        }
        catch (DecoderFallbackException)
        {
            return printed;
        }
    }

    /// <summary>The byte a sequence starting at <paramref name="at"/> (a backslash) names, and its length; null if none.</summary>
    private static (byte Value, int Length)? Sequence(string s, int at)
    {
        char At(int offset) => at + offset < s.Length ? s[at + offset] : '\0';

        if (At(1) == 'M' && At(2) == '-' && At(3) != '\0')
        {
            return ((byte)(At(3) | 0x80), 4);
        }

        if (At(1) == 'M' && At(2) == '^' && At(3) != '\0')
        {
            return ((byte)(Control(At(3)) | 0x80), 4);
        }

        // Nothing else: ps encodes with VIS_TAB | VIS_NL | VIS_NOSLASH, so a tab or newline arrives as \^I or \^J, and a
        // backslash in a real command line (-Dre=\d+\s, C:\new) is printed as-is -- decoding C-style escapes would
        // rewrite it.
        return At(1) == '^' && At(2) != '\0' ? (Control(At(2)), 3) : null;
    }

    private static byte Control(char c) => c == '?' ? (byte)0x7F : (byte)(c & 0x1F);
}
