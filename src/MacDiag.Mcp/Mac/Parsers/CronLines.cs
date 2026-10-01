using System.Text.RegularExpressions;

namespace MacDiag.Mcp.Mac.Parsers;

/// <param name="Schedule">The five time fields, or the @keyword.</param>
/// <param name="User">The sixth field of /etc/crontab; null in a user's own crontab, which has none.</param>
public sealed record CronLine(string Schedule, string? User, string Command);

/// <summary>crontab(5): comments, settings (NAME=value) and blank lines are not jobs.</summary>
public static partial class CronLines
{
    public static IReadOnlyList<CronLine> Parse(string text, bool hasUserField)
    {
        ArgumentNullException.ThrowIfNull(text);

        var jobs = new List<CronLine>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || Setting().IsMatch(line))
            {
                continue;
            }

            var fields = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            var timeFields = fields[0].StartsWith('@') ? 1 : 5;
            var commandStart = timeFields + (hasUserField ? 1 : 0);
            if (fields.Length <= commandStart)
            {
                continue;
            }

            jobs.Add(new CronLine(
                string.Join(' ', fields[..timeFields]),
                hasUserField ? fields[timeFields] : null,
                string.Join(' ', fields[commandStart..])));
        }

        return jobs;
    }

    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_]*\s*=")]
    private static partial Regex Setting();
}
