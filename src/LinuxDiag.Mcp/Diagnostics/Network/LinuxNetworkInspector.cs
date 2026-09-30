using System.Net;
using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Diagnostics.Containers;
using LinuxDiag.Mcp.Diagnostics.Handles;
using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Diagnostics.Network;

public sealed class LinuxNetworkInspector(IProcessTable processes, IContainerInspector containers, LinuxDiagOptions options)
    : INetworkInspector
{
    private static readonly (string File, TransportProtocol Protocol)[] Tables =
        [("tcp", TransportProtocol.Tcp), ("tcp6", TransportProtocol.Tcp), ("udp", TransportProtocol.Udp), ("udp6", TransportProtocol.Udp)];

    public async Task<NetworkEndpoints> EndpointsAsync(
        int? port, int? processId, bool listeningOnly, CancellationToken cancellationToken)
    {
        var table = processes.Read(cancellationToken);
        var catalog = await containers.ListAsync(table, cancellationToken).ConfigureAwait(false);
        var walk = DescriptorWalk.All(table, cancellationToken);
        var owners = SocketOwners.ByInode(walk, ContainerJoin.ById(catalog));

        var endpoints = new List<NetworkEndpoint>();
        foreach (var (file, protocol) in Tables)
        {
            foreach (var (ns, text) in NetworkNamespaces.Read(table, file))
            {
                endpoints.AddRange(SocketTable.Parse(text).Select(entry => ToEndpoint(entry, protocol, ns, owners)));
            }
        }

        var matched = endpoints
            .Where(e => port is null || e.LocalPort == port || e.RemotePort == port)
            .Where(e => processId is null || e.Owners.Any(o => o.ProcessId == processId))
            .Where(e => !listeningOnly || e.State == "Listen" || e.Protocol == TransportProtocol.Udp)
            .OrderBy(e => e.Protocol)
            .ThenBy(e => e.LocalPort)
            .ThenBy(e => e.Owners.Count == 0 ? int.MaxValue : e.Owners[0].ProcessId)
            .ToList();

        var limitations = new List<string>(catalog.Limitations);
        if (walk.UnreadableProcesses > 0)
        {
            limitations.Add($"{walk.UnreadableProcesses} processes' open files could not be read, so sockets they hold " +
                            "are listed without an owner; run the server as root.");
        }

        if (NetworkNamespaces.HiddenLimitation(table) is { } hidden)
        {
            limitations.Add(hidden);
        }

        var host = table.Processes.FirstOrDefault(p => p.ProcessId == Environment.ProcessId)?.NetworkNamespace;
        return new NetworkEndpoints(
            matched.Take(options.MaxResults).ToList(), matched.Count, matched.Count > options.MaxResults, limitations, host);
    }

    internal static NetworkEndpoint ToEndpoint(
        SocketEntry entry, TransportProtocol protocol, string ns, IReadOnlyDictionary<long, IReadOnlyList<SocketOwner>> owners)
    {
        // A listening or unconnected socket's remote end is all zeros: not an address worth printing.
        var unconnected = entry.RemotePort == 0 &&
                          (entry.RemoteAddress.Equals(IPAddress.Any) || entry.RemoteAddress.Equals(IPAddress.IPv6Any));
        return new NetworkEndpoint(
            protocol, entry.LocalAddress.ToString(), entry.LocalPort,
            unconnected ? null : entry.RemoteAddress.ToString(), unconnected ? null : entry.RemotePort,
            protocol == TransportProtocol.Tcp ? SocketTable.TcpStateName(entry.State) : null,
            entry.Inode == 0 ? [] : owners.GetValueOrDefault(entry.Inode) ?? [],
            ns);
    }
}
