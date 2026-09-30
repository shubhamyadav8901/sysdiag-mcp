using System.Globalization;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <param name="Path">The bound name: a path, "@name" for an abstract socket, or null for an unnamed one.</param>
public sealed record UnixSocketEntry(int Type, int State, bool Listening, long Inode, string? Path);

/// <summary><c>/proc/net/unix</c>.</summary>
public static class UnixSockets
{
    /// <summary>__SO_ACCEPTCON: the socket is listening.</summary>
    private const int AcceptConnections = 0x10000;

    public static IReadOnlyList<UnixSocketEntry> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var entries = new List<UnixSocketEntry>();
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Skip(1))
        {
            // Num RefCount Protocol Flags Type St Inode [Path]: the path may hold spaces, so the first seven
            // fields are taken one by one and the path is whatever remains.
            var fields = new string[7];
            var position = 0;
            for (var i = 0; i < fields.Length; i++)
            {
                while (position < line.Length && line[position] == ' ')
                {
                    position++;
                }

                var end = line.IndexOf(' ', position);
                end = end < 0 ? line.Length : end;
                fields[i] = line[position..end];
                position = end;
            }

            if (fields[6].Length == 0)
            {
                throw new FormatException($"/proc/net/unix line is too short: '{line}'.");
            }

            var path = position < line.Length ? line[position..].Trim() : string.Empty;
            entries.Add(new UnixSocketEntry(
                int.Parse(fields[4], NumberStyles.HexNumber, CultureInfo.InvariantCulture),
                int.Parse(fields[5], NumberStyles.HexNumber, CultureInfo.InvariantCulture),
                (int.Parse(fields[3], NumberStyles.HexNumber, CultureInfo.InvariantCulture) & AcceptConnections) != 0,
                long.Parse(fields[6], NumberStyles.None, CultureInfo.InvariantCulture),
                path.Length == 0 ? null : path));
        }

        return entries;
    }

    public static string KindName(int type) => type switch
    {
        1 => "UnixStream",
        2 => "UnixDatagram",
        5 => "UnixSeqPacket",
        _ => "Unix",
    };
}
