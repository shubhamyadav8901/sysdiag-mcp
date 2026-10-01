using System.Text.RegularExpressions;

namespace MacDiag.Mcp.Mac.Parsers;

public sealed record LoadedKext(string BundleId, string Version);

/// <summary>kmutil showloaded: kextstat's columns, Index Refs Address Size Wired Name (Version) UUID &lt;Linked Against&gt;.</summary>
/// <remarks>Read leniently (spec M8): a row is an index, a reference count, an address (0 for the kernel's own
/// interfaces), two sizes, then a bundle id with its version in parentheses. The header and kmutil's notices on
/// Apple Silicon ("No variant specified...") are not rows, and the parser never depends on finding the header.</remarks>
public static partial class KextList
{
    public static IReadOnlyList<LoadedKext> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        return text.Split('\n')
            .Select(line => Row().Match(line))
            .Where(match => match.Success)
            .Select(match => new LoadedKext(match.Groups[1].Value, match.Groups[2].Value))
            .ToList();
    }

    /// <summary>Lines that are neither rows, the header, a notice nor blank: output in a shape this parser does not know.</summary>
    public static bool HasUnrecognisedLines(string text) =>
        (text ?? string.Empty).Split('\n')
            .Select(l => l.Trim())
            .Any(l => l.Length > 0 && !Row().IsMatch(l) && !l.StartsWith("Index ", StringComparison.Ordinal) &&
                      !l.StartsWith("No variant specified", StringComparison.Ordinal));

    [GeneratedRegex(@"^\s*\d+\s+\d+\s+(?:0x[0-9a-fA-F]+|0)\s+\S+\s+\S+\s+(\S+)\s+\(([^)]*)\)")]
    private static partial Regex Row();
}
