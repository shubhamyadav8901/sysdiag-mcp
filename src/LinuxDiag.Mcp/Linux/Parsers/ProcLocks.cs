using System.Globalization;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <param name="Waiting">A "->" line: a process blocked waiting for this lock, not holding it.</param>
/// <param name="ProcessId">For FLOCK and OFD locks, the process that created the lock -- possibly gone; -1 for OFD.</param>
public sealed record LockEntry(
    int Id, bool Waiting, string Type, string Mode, string Access, int ProcessId, uint DeviceMajor, uint DeviceMinor, long Inode);

/// <summary><c>/proc/locks</c>, and the same format after an fdinfo <c>lock:</c> prefix.</summary>
public static class ProcLocks
{
    public static IReadOnlyList<LockEntry> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(ParseLine).ToList();
    }

    /// <summary>Every line that parses, and how many did not: one odd line must not sink the answer.</summary>
    /// <remarks>The kernel prints <c>&lt;none&gt;</c> for a lock on a file with no inode, which no caller can match anyway.</remarks>
    public static (IReadOnlyList<LockEntry> Entries, int Skipped) ParseLenient(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var entries = new List<LockEntry>();
        var skipped = 0;
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                entries.Add(ParseLine(line));
            }
            catch (FormatException)
            {
                skipped++;
            }
        }

        return (entries, skipped);
    }

    /// <summary>One line: <c>id: [->] TYPE MODE ACCESS PID MAJ:MIN:INODE START END</c>, device in hex.</summary>
    public static LockEntry ParseLine(string line)
    {
        ArgumentNullException.ThrowIfNull(line);

        var fields = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
        var i = 0;
        var waiting = fields.Length > 1 && fields[1] == "->";
        var first = waiting ? 2 : 1;
        if (fields.Length < first + 5)
        {
            throw new FormatException($"/proc/locks line is too short: '{line}'.");
        }

        var id = int.Parse(fields[i].TrimEnd(':'), NumberStyles.None, CultureInfo.InvariantCulture);
        i = first;
        var type = fields[i++];
        var mode = fields[i++];
        var access = fields[i++];
        var pid = int.Parse(fields[i++], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
        var device = fields[i].Split(':');
        if (device.Length != 3)
        {
            throw new FormatException($"/proc/locks line has no MAJ:MIN:INODE field: '{line}'.");
        }

        return new LockEntry(
            id, waiting, type, mode, access, pid,
            uint.Parse(device[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture),
            uint.Parse(device[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture),
            long.Parse(device[2], NumberStyles.None, CultureInfo.InvariantCulture));
    }
}
