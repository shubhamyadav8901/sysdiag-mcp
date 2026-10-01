using System.Globalization;

namespace MacDiag.Mcp.Diagnostics.Network;

public enum TransportProtocol
{
    Tcp,
    Udp,
}

public sealed record SocketOwner(int ProcessId, string ProcessName);

/// <param name="Owners">Every process holding the socket: prefork workers and inherited listeners share one.</param>
public sealed record NetworkEndpoint(
    TransportProtocol Protocol, string LocalAddress, int LocalPort, string? RemoteAddress, int? RemotePort,
    string? State, IReadOnlyList<SocketOwner> Owners);

public sealed record NetworkEndpoints(
    IReadOnlyList<NetworkEndpoint> Endpoints, int TotalMatched, bool Truncated, IReadOnlyList<string> Limitations);

public interface INetworkInspector
{
    Task<NetworkEndpoints> EndpointsAsync(int? port, int? processId, bool listeningOnly, CancellationToken cancellationToken);
}

public sealed record PipeOwner(int ProcessId, string ProcessName);

/// <param name="Kind">UnixSocket or Fifo.</param>
/// <param name="Listening">Always null on macOS: its lsof does not report a unix socket's state, and false would read as a fact.</param>
/// <param name="ConnectedCount">Descriptors open on this name, across every holder.</param>
public sealed record NamedPipe(string Name, string Kind, bool? Listening, int ConnectedCount, IReadOnlyList<PipeOwner> Owners);

public sealed record NamedPipeList(IReadOnlyList<NamedPipe> Pipes, int TotalMatched, bool Truncated, IReadOnlyList<string> Limitations);

public interface IPipeInspector
{
    Task<NamedPipeList> ListAsync(string? nameFilter, CancellationToken cancellationToken);
}

/// <summary>lsof's numeric socket name: "local" or "local->remote", each "host:port", IPv6 hosts in brackets.</summary>
public static class LsofAddress
{
    public static (string Local, int LocalPort, string? Remote, int? RemotePort)? Parse(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        var ends = name.Split("->", 2);
        if (End(ends[0]) is not { } local)
        {
            return null;
        }

        if (ends.Length == 1)
        {
            return (local.Host, local.Port, null, null);
        }

        return End(ends[1]) is { } remote ? (local.Host, local.Port, remote.Host, remote.Port) : null;
    }

    private static (string Host, int Port)? End(string text)
    {
        var colon = text.LastIndexOf(':');
        if (colon <= 0 || !int.TryParse(text[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var port))
        {
            return null;
        }

        var host = text[..colon];
        return (host.StartsWith('[') && host.EndsWith(']') ? host[1..^1] : host, port);
    }
}
