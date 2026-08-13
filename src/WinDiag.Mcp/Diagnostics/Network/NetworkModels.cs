namespace WinDiag.Mcp.Diagnostics.Network;

/// <summary>Transport protocol of an endpoint.</summary>
public enum TransportProtocol
{
    Tcp,
    Udp
}

/// <summary>One local network endpoint and the process that owns it.</summary>
/// <param name="State">TCP connection state. Null for UDP, which is connectionless.</param>
/// <param name="ProcessName">
/// Null when the owning process has exited or could not be opened. The PID is still reported, since it
/// is what the kernel returned.
/// </param>
public sealed record NetworkEndpoint(
    TransportProtocol Protocol,
    string LocalAddress,
    int LocalPort,
    string? RemoteAddress,
    int? RemotePort,
    string? State,
    int OwningProcessId,
    string? ProcessName);

/// <summary>Result of enumerating network endpoints.</summary>
public sealed record NetworkEndpointsResult(
    IReadOnlyList<NetworkEndpoint> Endpoints,
    int TotalMatched,
    bool Truncated);

/// <summary>Enumerates local TCP and UDP endpoints with their owning process.</summary>
public interface INetworkInspector
{
    NetworkEndpointsResult List(
        int? port,
        int? processId,
        bool listeningOnly,
        CancellationToken cancellationToken);
}
