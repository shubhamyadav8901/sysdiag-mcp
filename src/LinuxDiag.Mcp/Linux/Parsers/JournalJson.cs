using System.Globalization;
using System.Text;
using System.Text.Json;

namespace LinuxDiag.Mcp.Linux.Parsers;

public sealed record JournalEntry(
    DateTimeOffset Time, int Priority, string? Identifier, string? Command, string? Unit, int? ProcessId, string? Message);

/// <summary><c>journalctl -o json</c>: one object per line.</summary>
public static class JournalJson
{
    /// <returns>The entries, and how many lines could not be read.</returns>
    public static (IReadOnlyList<JournalEntry> Entries, int Skipped) Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var entries = new List<JournalEntry>();
        var skipped = 0;
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                var micros = long.Parse(Text(root, "__REALTIME_TIMESTAMP") ?? "0", NumberStyles.None, CultureInfo.InvariantCulture);
                entries.Add(new JournalEntry(
                    DateTimeOffset.FromUnixTimeMilliseconds(micros / 1000).AddTicks(micros % 1000 * 10),
                    int.TryParse(Text(root, "PRIORITY"), NumberStyles.None, CultureInfo.InvariantCulture, out var priority) ? priority : 6,
                    Text(root, "SYSLOG_IDENTIFIER"),
                    Text(root, "_COMM"),
                    Text(root, "_SYSTEMD_UNIT"),
                    int.TryParse(Text(root, "_PID"), NumberStyles.None, CultureInfo.InvariantCulture, out var pid) ? pid : null,
                    Text(root, "MESSAGE")));
            }
            catch (Exception ex) when (ex is JsonException or FormatException or OverflowException)
            {
                skipped++;
            }
        }

        return (entries, skipped);
    }

    /// <summary>A field's value as text, whichever of the journal's shapes it takes.</summary>
    /// <remarks>
    /// A string is itself; a byte array (a value that is not UTF-8) is decoded with replacement characters;
    /// an array of strings (a field given more than once) is joined; null (a value over 4096 bytes) stays null.
    /// </remarks>
    private static string? Text(JsonElement root, string field)
    {
        if (!root.TryGetProperty(field, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Array when value.EnumerateArray().All(e => e.ValueKind == JsonValueKind.Number) =>
                Encoding.UTF8.GetString(value.EnumerateArray().Select(e => (byte)e.GetInt32()).ToArray()),
            JsonValueKind.Array => string.Join("\n", value.EnumerateArray().Select(e => e.ToString())),
            _ => null,
        };
    }
}
