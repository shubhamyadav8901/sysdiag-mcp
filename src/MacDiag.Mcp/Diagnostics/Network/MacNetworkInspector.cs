using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Mac;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Network;

/// <summary>TCP and UDP endpoints with every owning process, from lsof -i -Ts.</summary>
/// <remarks>
/// lsof lists a socket once per process holding it. Entries are joined into one endpoint by the socket's kernel
/// address, which is what makes them the same socket: grouping by address instead would merge an IPv4 and an IPv6
/// listener on *:80, or two SO_REUSEPORT sockets, into one.
/// </remarks>
public sealed class MacNetworkInspector(IExternalCommand commands, MacDiagOptions options) : INetworkInspector
{
    public async Task<NetworkEndpoints> EndpointsAsync(int? port, int? processId, bool listeningOnly, CancellationToken cancellationToken)
    {
        var listed = await Lsof.RunAsync(commands, ["-i", "-Ts"], fullListing: false, options.ExternalToolTimeout, cancellationToken)
            .ConfigureAwait(false);

        var unreadable = 0;
        var endpoints = new List<NetworkEndpoint>();
        foreach (var group in listed
            .SelectMany(p => p.Files.Select(f => (Process: p, File: f)))
            .Where(x => x.File.Protocol is "TCP" or "UDP")
            .GroupBy(x => x.File.KernelAddress ?? $"{x.File.Type}|{x.File.Protocol}|{x.File.Name}|{x.File.TcpState}", StringComparer.Ordinal))
        {
            var (_, file) = group.First();
            if (LsofAddress.Parse(file.Name ?? string.Empty) is not { } address)
            {
                unreadable++;
                continue;
            }

            var owners = group.Select(x => new SocketOwner(x.Process.ProcessId, x.Process.Command))
                .DistinctBy(o => o.ProcessId).OrderBy(o => o.ProcessId).ToList();
            endpoints.Add(new NetworkEndpoint(
                file.Protocol == "TCP" ? TransportProtocol.Tcp : TransportProtocol.Udp,
                address.Local, address.LocalPort, address.Remote, address.RemotePort,
                file.Protocol == "TCP" ? State(file.TcpState) : null, owners));
        }

        var matched = endpoints
            .Where(e => port is null || e.LocalPort == port || e.RemotePort == port)
            .Where(e => processId is null || e.Owners.Any(o => o.ProcessId == processId))
            .Where(e => !listeningOnly || e.State == "Listen" || e.Protocol == TransportProtocol.Udp)
            .OrderBy(e => e.Protocol).ThenBy(e => e.LocalPort).ThenBy(e => e.Owners.Count > 0 ? e.Owners[0].ProcessId : int.MaxValue)
            .ToList();
        var kept = matched.Take(options.MaxResults).ToList();

        List<string> limitations = [];
        if (unreadable > 0)
        {
            limitations.Add($"{unreadable} socket{(unreadable == 1 ? " has" : "s have")} an address lsof printed in a form this server " +
                            "does not read (for example *:*) and is not listed.");
        }

        return new NetworkEndpoints(kept, matched.Count, matched.Count > kept.Count, limitations);
    }

    /// <summary>lsof's TCP state (LISTEN, CLOSE_WAIT) as every server spells it: Listen, CloseWait.</summary>
    internal static string? State(string? lsofState) =>
        lsofState is null ? null
        : string.Concat(lsofState.Split('_', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => char.ToUpperInvariant(part[0]) + part[1..].ToLowerInvariant()));
}

/// <summary>Named unix sockets and FIFOs with their holders, from a full lsof listing.</summary>
public sealed class MacPipeInspector(IExternalCommand commands, MacDiagOptions options) : IPipeInspector
{
    internal const string ListeningNote =
        "macOS's lsof does not report whether a unix socket is listening, so Listening is unknown for every entry.";

    public async Task<NamedPipeList> ListAsync(string? nameFilter, CancellationToken cancellationToken)
    {
        var listed = await Lsof.RunAsync(commands, [], fullListing: true, options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);

        var pipes = listed
            .SelectMany(p => p.Files.Select(f => (Process: p, File: f)))
            .Where(x => x.File.Type is "unix" or "FIFO" && x.File.Name is { } name && name.StartsWith('/'))
            .Where(x => string.IsNullOrWhiteSpace(nameFilter) || x.File.Name!.Contains(nameFilter, StringComparison.OrdinalIgnoreCase))
            .GroupBy(x => (x.File.Name!, x.File.Type))
            .Select(g => new NamedPipe(
                g.Key.Item1, g.Key.Type == "FIFO" ? "Fifo" : "UnixSocket", null, g.Count(),
                g.Select(x => new PipeOwner(x.Process.ProcessId, x.Process.Command)).DistinctBy(o => o.ProcessId).OrderBy(o => o.ProcessId).ToList()))
            .OrderBy(p => p.Name, StringComparer.Ordinal)
            .ToList();
        var kept = pipes.Take(options.MaxResults).ToList();
        return new NamedPipeList(kept, pipes.Count, pipes.Count > kept.Count, [ListeningNote]);
    }
}
