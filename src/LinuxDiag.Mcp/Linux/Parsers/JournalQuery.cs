using System.Globalization;
using System.Text.RegularExpressions;
using LinuxDiag.Mcp.Linux.External;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <summary>What event_log_tail asks journalctl, built without I/O so it can be tested exactly.</summary>
public static partial class JournalQuery
{
    public const string Fields = "__REALTIME_TIMESTAMP,PRIORITY,SYSLOG_IDENTIFIER,_COMM,_SYSTEMD_UNIT,_PID,MESSAGE";

    private static readonly Dictionary<string, int[]> Levels = new(StringComparer.OrdinalIgnoreCase)
    {
        ["critical"] = [0, 1, 2],
        ["error"] = [3],
        ["warning"] = [4],
        ["information"] = [5, 6],
        ["verbose"] = [7],
    };

    /// <summary>windiag's severity names as syslog priorities: emerg, alert and crit are critical; notice and info are information.</summary>
    public static IReadOnlyList<int> Priorities(string[]? levels)
    {
        if (levels is null || levels.Length == 0)
        {
            return [0, 1, 2, 3, 4];
        }

        if (levels.Any(l => string.Equals(l?.Trim(), "all", StringComparison.OrdinalIgnoreCase)))
        {
            return [0, 1, 2, 3, 4, 5, 6, 7];
        }

        return levels
            .SelectMany(l => Levels.TryGetValue(l?.Trim() ?? string.Empty, out var priorities)
                ? priorities
                : throw new ArgumentException(
                    $"'{l}' is not a severity. Use one or more of: critical, error, warning, information, verbose, or 'all'.", nameof(levels)))
            .Distinct()
            .Order()
            .ToList();
    }

    /// <summary>The argument list. <c>-p</c> takes one range, so a set with a gap is fetched as its range and filtered after.</summary>
    public static IReadOnlyList<string> Arguments(
        string? unit, DateTimeOffset since, IReadOnlyList<int> priorities, string? provider, IReadOnlyList<string> matches, int limit)
    {
        var arguments = new List<string>
        {
            // --all: without it JSON output replaces any field over 4096 bytes with null -- a coredump's stack trace.
            "-o", "json", "--all", "--no-pager", "-r", "--output-fields=" + Fields,
            "-n", limit.ToString(CultureInfo.InvariantCulture),
            "--since", "@" + since.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            "-p", $"{priorities.Min()}..{priorities.Max()}",
        };
        if (unit is not null)
        {
            arguments.AddRange(["-u", unit]);
        }

        if (provider is not null)
        {
            arguments.Add("SYSLOG_IDENTIFIER=" + provider);
        }

        arguments.AddRange(matches);
        return arguments;
    }

    /// <summary>A caller's journal match, FIELD=value with an upper-case field name, the only form journalctl reads as a match.</summary>
    public static string Match(string value)
    {
        ExternalArgument.Check(value, "match");
        return FieldMatch().IsMatch(value)
            ? value
            : throw new ArgumentException($"'{value}' is not a journal match. Use FIELD=value, for example _UID=1000 or _COMM=nginx.", "match");
    }

    [GeneratedRegex(@"^[A-Z0-9_]+=.+$")]
    private static partial Regex FieldMatch();
}
