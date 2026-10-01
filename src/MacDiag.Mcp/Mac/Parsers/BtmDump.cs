using System.Globalization;
using System.Text.RegularExpressions;

namespace MacDiag.Mcp.Mac.Parsers;

/// <param name="Uid">The account from the "Records for UID n" header the item sits under.</param>
/// <param name="Type">"legacy daemon", "login item", "agent"... without the hex code sfltool appends.</param>
/// <param name="Enabled">Both "enabled" and "allowed" are among the disposition's words.</param>
/// <param name="Missing">Expected keys the item did not carry, so a null is never read as "none" (spec M8).</param>
public sealed record BtmItem(
    int Uid, string? Name, string? Type, IReadOnlyList<string> Disposition, bool Enabled, string? Identifier, string? Url,
    string? ExecutablePath, string? DeveloperName, string? TeamId, IReadOnlyList<string> Missing);

/// <summary>sfltool dumpbtm: Background Task Management's records, undocumented and read leniently.</summary>
/// <remarks>
/// Items are numbered blocks (" #1:") of "Key: value" lines, under a "Records for UID n" header per account. A
/// disposition is split into words, because "disallowed" contains "allowed" and "disabled" ends like "enabled".
/// </remarks>
public static partial class BtmDump
{
    private static readonly string[] Expected = ["Name", "Type", "Disposition"];

    public static IReadOnlyList<BtmItem> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var items = new List<BtmItem>();
        var uid = -1;
        Dictionary<string, string>? block = null;

        void Close()
        {
            if (block is not null)
            {
                items.Add(Item(uid, block));
            }

            block = null;
        }

        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (RecordsFor().Match(line) is { Success: true } records)
            {
                Close();
                uid = int.Parse(records.Groups[1].Value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
            }
            else if (ItemMarker().IsMatch(line))
            {
                Close();
                block = new Dictionary<string, string>(StringComparer.Ordinal);
            }
            else if (line.StartsWith("=====", StringComparison.Ordinal))
            {
                Close();
            }
            else if (block is not null && line.IndexOf(": ", StringComparison.Ordinal) is > 0 and var colon)
            {
                block.TryAdd(line[..colon].Trim(), line[(colon + 2)..].Trim());
            }
        }

        Close();
        return items;
    }

    private static BtmItem Item(int uid, Dictionary<string, string> keys)
    {
        var disposition = keys.TryGetValue("Disposition", out var text)
            ? text.Split(['[', ']', ',', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries).Where(w => !w.StartsWith("(0x", StringComparison.Ordinal)).ToList()
            : [];
        var type = keys.GetValueOrDefault("Type") is { } t ? HexSuffix().Replace(t, string.Empty).Trim() : null;
        return new BtmItem(
            uid, keys.GetValueOrDefault("Name"), type, disposition, disposition.Contains("enabled") && disposition.Contains("allowed"),
            keys.GetValueOrDefault("Identifier"), keys.GetValueOrDefault("URL"), keys.GetValueOrDefault("Executable Path"),
            keys.GetValueOrDefault("Developer Name"), keys.GetValueOrDefault("Team Identifier"),
            Expected.Where(k => !keys.ContainsKey(k)).ToList());
    }

    [GeneratedRegex(@"^Records for UID (-?\d+)")]
    private static partial Regex RecordsFor();

    [GeneratedRegex(@"^#\d+:$")]
    private static partial Regex ItemMarker();

    [GeneratedRegex(@"\s*\(0x[0-9a-fA-F]+\)$")]
    private static partial Regex HexSuffix();
}
