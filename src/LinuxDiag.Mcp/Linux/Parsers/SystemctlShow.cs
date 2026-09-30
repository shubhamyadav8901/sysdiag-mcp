using System.Globalization;
using System.Text.RegularExpressions;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <summary>One unit's properties from <c>systemctl show</c>. A property may repeat (ExecStart).</summary>
public sealed class SystemdUnit
{
    private readonly Dictionary<string, List<string>> _values = new(StringComparer.Ordinal);

    internal void Add(string key, string value)
    {
        if (!_values.TryGetValue(key, out var list))
        {
            _values[key] = list = [];
        }

        list.Add(value);
    }

    /// <summary>The first value, or null when systemd did not print the property.</summary>
    public string? this[string key] => _values.TryGetValue(key, out var list) ? list[0] : null;

    public IReadOnlyList<string> All(string key) => _values.TryGetValue(key, out var list) ? list : [];

    /// <summary>A space-separated list property (Requires, WantedBy, DropInPaths).</summary>
    public IReadOnlyList<string> List(string key) =>
        this[key]?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? [];
}

/// <param name="Path">The program systemd runs.</param>
/// <param name="CommandLine">Its argv as systemd prints it, variables unexpanded.</param>
public sealed record ExecCommand(string Path, string CommandLine);

public static partial class SystemctlShow
{
    /// <summary>One block per unit, blank-line separated, properties in whatever order systemd prints them.</summary>
    public static IReadOnlyList<SystemdUnit> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var units = new List<SystemdUnit>();
        SystemdUnit? current = null;
        foreach (var line in text.Split('\n'))
        {
            if (line.Length == 0)
            {
                current = null;
                continue;
            }

            var equals = line.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0)
            {
                continue;
            }

            if (current is null)
            {
                current = new SystemdUnit();
                units.Add(current);
            }

            current.Add(line[..equals], line[(equals + 1)..]);
        }

        return units;
    }

    /// <summary>
    /// The program and argv of one ExecStart value: <c>{ path=… ; argv[]=… ; ignore_errors=… ; … }</c>.
    /// </summary>
    public static ExecCommand? Command(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var match = ExecPattern().Match(value);
        return match.Success ? new ExecCommand(match.Groups["path"].Value, match.Groups["argv"].Value) : null;
    }

    /// <summary>A <c>--timestamp=utc</c> value such as "Wed 2026-09-30 16:25:21 UTC", or null for empty and n/a.</summary>
    public static DateTimeOffset? Timestamp(string? value) =>
        DateTimeOffset.TryParseExact(
            value, "ddd yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var time)
            ? time
            : null;

    [GeneratedRegex(@"path=(?<path>[^ ]+) ; argv\[\]=(?<argv>.*?) ; [a-z_]+=")]
    private static partial Regex ExecPattern();
}
