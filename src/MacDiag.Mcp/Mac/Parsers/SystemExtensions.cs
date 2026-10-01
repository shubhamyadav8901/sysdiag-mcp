using System.Text.RegularExpressions;

namespace MacDiag.Mcp.Mac.Parsers;

/// <param name="Kind">The extension point from the "--- " line above the row: network, endpoint security, driver.</param>
/// <param name="State">The bracketed state: "activated enabled", "terminated waiting to uninstall on reboot".</param>
public sealed record SystemExtension(string Kind, bool Enabled, bool Active, string? TeamId, string BundleId, string? Version, string? Name, string State);

/// <summary>systemextensionsctl list: an undocumented, TAB-separated table under one "--- kind" line per extension point.</summary>
/// <remarks>Read leniently (spec M8): the enabled and active columns are empty when false, and a row is recognised by its
/// "bundle.id (version)" column, never by its position after the header.</remarks>
public static partial class SystemExtensions
{
    public static IReadOnlyList<SystemExtension> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var extensions = new List<SystemExtension>();
        var kind = string.Empty;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.StartsWith("--- ", StringComparison.Ordinal))
            {
                kind = line[4..].Trim();
                continue;
            }

            var fields = line.Split('\t');
            // The header's own "bundleID (version)" has the shape of a row.
            if (fields.Length < 6 || fields[0].Trim() == "enabled" || BundleAndVersion().Match(fields[3].Trim()) is not { Success: true } bundle)
            {
                continue;
            }

            extensions.Add(new SystemExtension(
                kind, fields[0].Trim() == "*", fields[1].Trim() == "*", NullIfEmpty(fields[2]), bundle.Groups[1].Value,
                bundle.Groups[2].Value, NullIfEmpty(fields[4]), string.Join('\t', fields[5..]).Trim().Trim('[', ']')));
        }

        return extensions;
    }

    /// <summary>Whether the output says, in its own words, that there are no extensions.</summary>
    public static bool SaysNone(string text) => NoneLine().IsMatch(text ?? string.Empty);

    private static string? NullIfEmpty(string value) => value.Trim() is { Length: > 0 } trimmed ? trimmed : null;

    [GeneratedRegex(@"^(\S+) \(([^)]*)\)$")]
    private static partial Regex BundleAndVersion();

    [GeneratedRegex(@"(?m)^\s*0 extension\(s\)\s*$")]
    private static partial Regex NoneLine();
}
