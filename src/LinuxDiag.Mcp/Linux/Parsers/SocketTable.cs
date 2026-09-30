using System.Globalization;
using System.Net;

namespace LinuxDiag.Mcp.Linux.Parsers;

public enum TransportProtocol
{
    Tcp,
    Udp,
}

/// <param name="Inode">The socket's inode; 0 when there is no socket behind the entry (TIME_WAIT).</param>
public sealed record SocketEntry(
    IPAddress LocalAddress, int LocalPort, IPAddress RemoteAddress, int RemotePort, int State, long UserId, long Inode);

/// <summary><c>/proc/net/{tcp,tcp6,udp,udp6}</c>.</summary>
public static class SocketTable
{
    public static IReadOnlyList<SocketEntry> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var entries = new List<SocketEntry>();
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Skip(1))
        {
            // sl local remote st tx:rx tr:when retrnsmt uid timeout inode ...
            var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 10)
            {
                throw new FormatException($"/proc/net socket line is too short: '{line.Trim()}'.");
            }

            var (localAddress, localPort) = Endpoint(fields[1]);
            var (remoteAddress, remotePort) = Endpoint(fields[2]);
            entries.Add(new SocketEntry(
                localAddress, localPort, remoteAddress, remotePort,
                int.Parse(fields[3], NumberStyles.HexNumber, CultureInfo.InvariantCulture),
                long.Parse(fields[7], NumberStyles.None, CultureInfo.InvariantCulture),
                long.Parse(fields[9], NumberStyles.None, CultureInfo.InvariantCulture)));
        }

        return entries;
    }

    /// <summary>TCP state names, as windiag spells its own.</summary>
    public static string? TcpStateName(int state) => state switch
    {
        1 => "Established",
        2 => "SynSent",
        3 => "SynReceived",
        4 => "FinWait1",
        5 => "FinWait2",
        6 => "TimeWait",
        7 => "Closed",
        8 => "CloseWait",
        9 => "LastAck",
        10 => "Listen",
        11 => "Closing",
        12 => "NewSynReceived",
        _ => null,
    };

    private static (IPAddress Address, int Port) Endpoint(string text)
    {
        var colon = text.IndexOf(':', StringComparison.Ordinal);
        if (colon < 0)
        {
            throw new FormatException($"/proc/net address has no port: '{text}'.");
        }

        return (Address(text[..colon]), int.Parse(text.AsSpan(colon + 1), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
    }

    /// <summary>The kernel prints the address as 32-bit words in host order, little-endian on x86-64.</summary>
    private static IPAddress Address(string hex)
    {
        var bytes = Convert.FromHexString(hex);
        if (bytes.Length is not (4 or 16))
        {
            throw new FormatException($"/proc/net address '{hex}' is neither IPv4 nor IPv6.");
        }

        for (var word = 0; word < bytes.Length; word += 4)
        {
            Array.Reverse(bytes, word, 4);
        }

        return new IPAddress(bytes);
    }
}
