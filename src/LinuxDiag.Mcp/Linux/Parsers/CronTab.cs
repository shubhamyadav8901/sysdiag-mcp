using System.Text.RegularExpressions;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <param name="Schedule">Five fields, or an @keyword such as @reboot.</param>
/// <param name="User">The account, in a system crontab (/etc/crontab, /etc/cron.d); null in a user's own.</param>
public sealed record CronEntry(string Schedule, string? User, string Command);

public static partial class CronTab
{
    public static IReadOnlyList<CronEntry> Parse(string text, bool systemFormat)
    {
        ArgumentNullException.ThrowIfNull(text);

        var entries = new List<CronEntry>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || Assignment().IsMatch(line))
            {
                continue;
            }

            var position = 0;
            var scheduleFields = line.StartsWith('@') ? 1 : 5;
            var schedule = new List<string>();
            for (var i = 0; i < scheduleFields && Token(line, ref position) is { } token; i++)
            {
                schedule.Add(token);
            }

            var user = systemFormat ? Token(line, ref position) : null;
            var command = position < line.Length ? line[position..].Trim() : string.Empty;
            if (schedule.Count == scheduleFields && command.Length > 0)
            {
                entries.Add(new CronEntry(string.Join(' ', schedule), user, command));
            }
        }

        return entries;
    }

    private static string? Token(string line, ref int position)
    {
        while (position < line.Length && line[position] is ' ' or '\t')
        {
            position++;
        }

        var start = position;
        while (position < line.Length && line[position] is not (' ' or '\t'))
        {
            position++;
        }

        return position > start ? line[start..position] : null;
    }

    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_]*\s*=")]
    private static partial Regex Assignment();
}

/// <summary>The program a command line runs, and the script when that program is an interpreter.</summary>
public static class LaunchCommand
{
    private static readonly HashSet<string> Interpreters = new(StringComparer.Ordinal)
    {
        "sh", "bash", "dash", "zsh", "ksh", "python", "python3", "perl", "ruby", "php", "node",
    };

    /// <remarks>
    /// Leading VAR=value assignments are skipped. An interpreter's script is the first argument that is not an
    /// option: for /bin/sh -e /opt/x/start.sh, what runs is start.sh, and that is the file whose origin matters.
    /// </remarks>
    public static (string? Program, string? Script) Split(string command)
    {
        ArgumentNullException.ThrowIfNull(command);

        var tokens = command.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries)
            .SkipWhile(t => t.Contains('=', StringComparison.Ordinal) && !t.StartsWith('/'))
            .ToList();
        if (tokens.Count == 0)
        {
            return (null, null);
        }

        var program = tokens[0];
        var script = Interpreters.Contains(Path.GetFileName(program))
            ? tokens.Skip(1).FirstOrDefault(t => !t.StartsWith('-'))
            : null;
        return (program, script);
    }
}
