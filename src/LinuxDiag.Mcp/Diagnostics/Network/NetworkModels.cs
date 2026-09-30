using LinuxDiag.Mcp.Diagnostics.Containers;
using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Diagnostics.Network;

public sealed record SocketOwner(int ProcessId, string ProcessName, ProcessContainer? Container);

/// <param name="Owners">Every process holding the socket: prefork workers and inherited listeners share one.</param>
/// <param name="NetworkNamespace">Which network namespace the endpoint lives in; a container's own, or the host's.</param>
public sealed record NetworkEndpoint(
    TransportProtocol Protocol, string LocalAddress, int LocalPort, string? RemoteAddress, int? RemotePort,
    string? State, IReadOnlyList<SocketOwner> Owners, string NetworkNamespace);

/// <param name="HostNetworkNamespace">The server's own namespace, so an endpoint elsewhere can be told apart.</param>
public sealed record NetworkEndpoints(
    IReadOnlyList<NetworkEndpoint> Endpoints, int TotalMatched, bool Truncated, IReadOnlyList<string> Limitations,
    string? HostNetworkNamespace);

public interface INetworkInspector
{
    Task<NetworkEndpoints> EndpointsAsync(int? port, int? processId, bool listeningOnly, CancellationToken cancellationToken);
}
