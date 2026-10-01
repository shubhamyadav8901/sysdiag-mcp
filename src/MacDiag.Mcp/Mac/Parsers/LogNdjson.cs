using System.Globalization;
using System.Text.Json;

namespace MacDiag.Mcp.Mac.Parsers;

/// <summary>The unified log's five message types, as log show names them.</summary>
public enum LogMessageType
{
    Fault,
    Error,
    Default,
    Info,
    Debug,
}

public enum LogLineKind
{
    Event,
    Loss,
}

/// <param name="Process">The last segment of processImagePath.</param>
public sealed record LogLine(
    LogLineKind Kind, DateTimeOffset Timestamp, string MessageType, string Process, string? Sender, string? Subsystem, string? Category,
    string? Message, int? ProcessId);

/// <summary>One line of log show --style ndjson.</summary>
/// <remarks>
/// Only logEvent objects are events. A lossEvent is kept so the result can say the system dropped messages; activity
/// and signpost events, an object with no eventType (the trailing {"count":…,"finished":1}), and anything that is
/// not a JSON object are skipped.
/// </remarks>
public static class LogNdjson
{
    private static readonly string[] TimestampFormats = ["yyyy-MM-dd HH:mm:ss.ffffffzzz", "yyyy-MM-dd HH:mm:sszzz"];

    public static LogLine? Parse(string line)
    {
        if (string.IsNullOrWhiteSpace(line) || !line.TrimStart().StartsWith('{'))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            var kind = Text(root, "eventType") switch
            {
                "logEvent" => LogLineKind.Event,
                "lossEvent" => LogLineKind.Loss,
                _ => (LogLineKind?)null,
            };
            if (kind is null ||
                !DateTimeOffset.TryParseExact(Text(root, "timestamp"), TimestampFormats, CultureInfo.InvariantCulture, DateTimeStyles.None, out var timestamp))
            {
                return null;
            }

            var image = Text(root, "processImagePath") ?? string.Empty;
            return new LogLine(
                kind.Value, timestamp, Text(root, "messageType") ?? string.Empty, image[(image.LastIndexOf('/') + 1)..],
                Empty(Text(root, "senderImagePath")), Empty(Text(root, "subsystem")), Empty(Text(root, "category")),
                Text(root, "eventMessage"),
                root.TryGetProperty("processID", out var pid) && pid.ValueKind == JsonValueKind.Number && pid.TryGetInt32(out var id) ? id : null);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? Text(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static string? Empty(string? value) => string.IsNullOrEmpty(value) ? null : value;
}

/// <summary>The shared level vocabulary, mapped onto the unified log's types (spec M7).</summary>
/// <remarks>macOS has no warning type; warning maps to default, which is most of all logging, so it is not a default level.</remarks>
public static class LogLevels
{
    public static readonly IReadOnlyList<LogMessageType> Defaults = [LogMessageType.Fault, LogMessageType.Error];

    public static IReadOnlyList<LogMessageType> Parse(string[]? levels)
    {
        if (levels is null || levels.Length == 0)
        {
            return Defaults;
        }

        var types = new List<LogMessageType>();
        foreach (var level in levels.Select(l => l.Trim().ToLowerInvariant()))
        {
            types.AddRange(level switch
            {
                "critical" => [LogMessageType.Fault],
                "error" => [LogMessageType.Error],
                "warning" => [LogMessageType.Default],
                "information" or "info" => [LogMessageType.Info],
                "verbose" or "debug" => [LogMessageType.Debug],
                "all" => Enum.GetValues<LogMessageType>(),
                _ => throw new ArgumentException(
                    $"'{level}' is not a level. Use critical, error, warning, information, verbose, or 'all'.", nameof(levels)),
            });
        }

        return types.Distinct().ToList();
    }

    /// <summary>Whether a message's type (as log prints it, any case) is one of these.</summary>
    public static bool Includes(IReadOnlyList<LogMessageType> types, string messageType) =>
        Enum.TryParse<LogMessageType>(messageType, ignoreCase: true, out var type) && types.Contains(type);

    public static string SharedName(string messageType) =>
        Enum.TryParse<LogMessageType>(messageType, ignoreCase: true, out var type)
            ? type switch
            {
                LogMessageType.Fault => "Critical",
                LogMessageType.Error => "Error",
                LogMessageType.Default => "Warning",
                LogMessageType.Info => "Information",
                _ => "Verbose",
            }
            : messageType;
}

/// <summary>The --predicate for log show, built so a caller's value can never close its quotes.</summary>
public static class LogPredicate
{
    public static string Build(string? process, string? subsystem, string? category, string? sender, IReadOnlyList<LogMessageType> types)
    {
        ArgumentNullException.ThrowIfNull(types);

        // The types come from the level enum, never from caller text, so they need no quoting.
        var clauses = new List<string>
        {
            "eventType == logEvent",
            "(" + string.Join(" OR ", types.Select(t => $"messageType == {t.ToString().ToLowerInvariant()}")) + ")",
        };
        foreach (var (field, value, parameter) in new[] { ("process", process, nameof(process)), ("subsystem", subsystem, nameof(subsystem)), ("category", category, nameof(category)), ("sender", sender, nameof(sender)) })
        {
            if (value is not null)
            {
                clauses.Add($"{field} == \"{Literal(value, parameter)}\"");
            }
        }

        return string.Join(" AND ", clauses);
    }

    /// <summary>A value for a double-quoted literal: no quote, no backslash, no control character, 1 to 256 characters.</summary>
    private static string Literal(string value, string parameter) =>
        value.Length is < 1 or > 256 || value.Any(c => c is '"' or '\\' || char.IsControl(c))
            ? throw new ArgumentException($"'{value}' cannot be used as a {parameter}: it must be 1-256 characters with no quote, backslash or control character.", parameter)
            : value;
}

/// <summary>The time windows the log is walked in, newest first, each further back than the last.</summary>
public static class LogWindows
{
    private static readonly int[] Edges = [0, 1, 5, 15, 30, 60, 120, 240, 480, 1440, 2880, 4320, 10080];

    /// <summary>Pairs of (from, to) minutes ago, the last clipped to <paramref name="minutes"/>.</summary>
    public static IReadOnlyList<(int From, int To)> For(int minutes)
    {
        var windows = new List<(int, int)>();
        for (var i = 0; i + 1 < Edges.Length && Edges[i] < minutes; i++)
        {
            windows.Add((Edges[i], Math.Min(Edges[i + 1], minutes)));
        }

        return windows;
    }

    /// <summary>log's --start/--end form, with the zone as -0700 so a daylight-saving hour is never ambiguous.</summary>
    public static string Format(DateTimeOffset time) =>
        time.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) +
        (time.Offset < TimeSpan.Zero ? "-" : "+") + time.Offset.Duration().ToString("hhmm", CultureInfo.InvariantCulture);
}
