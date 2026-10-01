using System.Text;

namespace MacDiag.Mcp.Mac.Parsers;

/// <summary>Undoes vis(3), which BSD ps applies to command lines: \M-x, \M^x, \^x, \ooo and the C escapes.</summary>
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

        if (At(1) == '^' && At(2) != '\0')
        {
            return (Control(At(2)), 3);
        }

        if (IsOctal(At(1)) && IsOctal(At(2)) && IsOctal(At(3)))
        {
            return ((byte)(((At(1) - '0') << 6) | ((At(2) - '0') << 3) | (At(3) - '0')), 4);
        }

        byte? named = At(1) switch
        {
            'n' => (byte)'\n',
            't' => (byte)'\t',
            'r' => (byte)'\r',
            'b' => (byte)'\b',
            'a' => 0x07,
            'v' => 0x0B,
            'f' => 0x0C,
            's' => (byte)' ',
            'E' => 0x1B,
            '\\' => (byte)'\\',
            _ => null,
        };
        return named is { } value ? (value, 2) : null;
    }

    private static byte Control(char c) => c == '?' ? (byte)0x7F : (byte)(c & 0x1F);

    private static bool IsOctal(char c) => c is >= '0' and <= '7';
}
