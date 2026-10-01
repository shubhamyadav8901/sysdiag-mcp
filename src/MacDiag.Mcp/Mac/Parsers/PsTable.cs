using System.Globalization;
using System.Text.RegularExpressions;

namespace MacDiag.Mcp.Mac.Parsers;

/// <summary>One line of <c>ps -axww -o pid=,ppid=,uid=,rss=,stat=,lstart=,args=</c>.</summary>
/// <param name="StartText">lstart as ps printed it (C locale): what an identity check compares, never the parsed form.</param>
public sealed record PsArgsRow(int ProcessId, int ParentProcessId, long UserId, long ResidentKiB, string State, DateTimeOffset? Start, string StartText, string Arguments);

/// <summary>One line of <c>ps -axww -o pid=,lstart=,comm=</c>: the start time is what proves it is the same process.</summary>
public sealed record PsCommRow(string StartText, string Command);

/// <summary>What the comm call said about each PID: its start and path, or that it was listed more than once.</summary>
public sealed record PsCommTable(IReadOnlyDictionary<int, PsCommRow> Commands, IReadOnlyList<int> Duplicates)
{
    /// <summary>The path for this PID only if the process that has it now started when the first call said it did.</summary>
    /// <remarks>A PID that exits and is reused between the two calls would otherwise lend the newcomer's path to the old row.</remarks>
    public string? For(int processId, string startText) =>
        Commands.TryGetValue(processId, out var row) && string.Equals(row.StartText, startText, StringComparison.Ordinal) ? row.Command : null;
}

/// <summary>macOS ps in two calls: the columns with args, then comm, which is the executable path and may hold spaces.</summary>
/// <remarks>
/// Two calls because both comm and args can hold spaces, so one line could not be split between them. lstart
/// is five tokens in the C locale ("Tue Oct  1 06:00:00 2024"), which is how args is found after it.
/// </remarks>
public static partial class PsTable
{
    public static (IReadOnlyList<PsArgsRow> Rows, int Unparsed) ParseArgs(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var rows = new List<PsArgsRow>();
        var unparsed = 0;
        foreach (var line in text.Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Trim().Length > 0))
        {
            var match = ArgsLine().Match(line);
            if (!match.Success ||
                !int.TryParse(match.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) ||
                !int.TryParse(match.Groups[2].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var ppid))
            {
                unparsed++;
                continue;
            }

            var startText = Spaces().Replace(match.Groups[6].Value, " ");
            DateTimeOffset? start = DateTime.TryParseExact(startText, "ddd MMM d HH:mm:ss yyyy", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeLocal, out var parsed) ? new DateTimeOffset(parsed) : null;
            rows.Add(new PsArgsRow(
                pid, ppid,
                long.Parse(match.Groups[3].Value, CultureInfo.InvariantCulture),
                long.Parse(match.Groups[4].Value, CultureInfo.InvariantCulture),
                match.Groups[5].Value, start, startText,
                VisDecode.Decode(match.Groups[7].Value)));
        }

        return (rows, unparsed);
    }

    public static PsCommTable ParseComm(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var commands = new Dictionary<int, PsCommRow>();
        var duplicates = new HashSet<int>();
        foreach (var line in text.Split('\n').Select(l => l.TrimEnd('\r')))
        {
            var match = CommLine().Match(line);
            if (!match.Success || !int.TryParse(match.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
            {
                continue;
            }

            // A PID listed twice means one line was forged or split: neither path can be trusted for it.
            if (!commands.TryAdd(pid, new PsCommRow(Spaces().Replace(match.Groups[2].Value, " "), VisDecode.Decode(match.Groups[3].Value))))
            {
                duplicates.Add(pid);
            }
        }

        foreach (var pid in duplicates)
        {
            commands.Remove(pid);
        }

        return new PsCommTable(commands, [.. duplicates.Order()]);
    }

    [GeneratedRegex(@"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})(?:\s+(.*))?$")]
    private static partial Regex ArgsLine();

    [GeneratedRegex(@"^\s*(\d+)\s+([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+)$")]
    private static partial Regex CommLine();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Spaces();
}
