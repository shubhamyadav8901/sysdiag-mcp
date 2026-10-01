using System.Globalization;
using System.Text.RegularExpressions;

namespace MacDiag.Mcp.Mac.Parsers;

/// <summary>sysctl -n with several names: one value per line, in the order asked.</summary>
public static partial class Sysctl
{
    /// <summary>Exactly <paramref name="expected"/> values; any other count throws, so a missing one cannot shift the rest.</summary>
    public static IReadOnlyList<string> ParseValues(string text, int expected)
    {
        ArgumentNullException.ThrowIfNull(text);

        var lines = text.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0).ToArray();
        return lines.Length == expected
            ? lines
            : throw new FormatException($"sysctl printed {lines.Length} values for {expected} names.");
    }

    /// <summary>kern.boottime is a struct, printed as "{ sec = N, usec = M } &lt;date&gt;"; null when the text is not that.</summary>
    public static DateTimeOffset? BootTime(string? value)
    {
        var match = BootTimePattern().Match(value ?? string.Empty);
        return match.Success && long.TryParse(match.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
    }

    [GeneratedRegex(@"\{\s*sec\s*=\s*(\d+)")]
    private static partial Regex BootTimePattern();
}
