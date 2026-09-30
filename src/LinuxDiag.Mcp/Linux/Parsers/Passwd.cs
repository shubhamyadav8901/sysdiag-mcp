using System.Globalization;

namespace LinuxDiag.Mcp.Linux.Parsers;

public sealed record PasswdEntry(string Name, long UserId, string Home);

/// <summary><c>/etc/passwd</c>, for naming the users that own processes.</summary>
public static class Passwd
{
    /// <remarks>The first entry for a uid wins, as getpwuid(3) returns it.</remarks>
    public static IReadOnlyDictionary<long, string> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var users = new Dictionary<long, string>();
        foreach (var line in text.Split('\n'))
        {
            var fields = line.Split(':');
            if (fields.Length >= 3 &&
                long.TryParse(fields[2], NumberStyles.None, CultureInfo.InvariantCulture, out var uid))
            {
                users.TryAdd(uid, fields[0]);
            }
        }

        return users;
    }

    /// <summary>Every account with its home directory, for finding per-user configuration.</summary>
    public static IReadOnlyList<PasswdEntry> Entries(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var entries = new List<PasswdEntry>();
        foreach (var line in text.Split('\n'))
        {
            var fields = line.Split(':');
            if (fields.Length >= 6 && long.TryParse(fields[2], NumberStyles.None, CultureInfo.InvariantCulture, out var uid))
            {
                entries.Add(new PasswdEntry(fields[0], uid, fields[5]));
            }
        }

        return entries;
    }
}
