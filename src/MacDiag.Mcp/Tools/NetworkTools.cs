using System.ComponentModel;
using System.Text;
using MacDiag.Mcp.Diagnostics.Network;
using ModelContextProtocol.Server;

namespace MacDiag.Mcp.Tools;

/// <summary>Structured result of <c>network_owners</c>.</summary>
public sealed record NetworkOwnersResult(
    string Summary, IReadOnlyList<NetworkEndpoint> Endpoints, int TotalMatched, bool Truncated, IReadOnlyList<string> Limitations);

/// <summary>Structured result of <c>named_pipes</c>.</summary>
public sealed record NamedPipesResult(
    string Summary, IReadOnlyList<NamedPipe> Pipes, int TotalMatched, bool Truncated, IReadOnlyList<string> Limitations);

[McpServerToolType]
public sealed class NetworkTools(INetworkInspector network, IPipeInspector pipes)
{
    [McpServerTool(
        Name = "network_owners",
        Title = "Network endpoints and owning processes",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "List TCP and UDP endpoints (IPv4 and IPv6) with every process that owns each socket - a prefork server's " +
        "workers all share one listening socket. Use it for 'what is already using port 8080', 'which process is " +
        "talking to that address', or to confirm a service is listening where it should be. Filter by port, owning " +
        "PID, or listening endpoints only. Containers run in a virtual machine on macOS; their sockets appear as the " +
        "VM's forwarders, not as the container's processes.")]
    public async Task<NetworkOwnersResult> NetworkOwners(
        [Description("Only endpoints using this local or remote port")] int? port = null,
        [Description("Only endpoints owned by this process id")] int? processId = null,
        [Description("Only listening TCP sockets and bound UDP endpoints, excluding established connections")] bool listeningOnly = false,
        CancellationToken cancellationToken = default)
    {
        var result = await network.EndpointsAsync(port, processId, listeningOnly, cancellationToken).ConfigureAwait(false);
        return new NetworkOwnersResult(RenderEndpoints(result), result.Endpoints, result.TotalMatched, result.Truncated, result.Limitations);
    }

    [McpServerTool(
        Name = "named_pipes",
        Title = "Named sockets and FIFOs",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "List named unix sockets and named FIFOs, with which processes hold each one. Use it when a client cannot " +
        "connect to a local service over its socket: a name nobody holds, or one held by an unexpected process, " +
        "shows up here. macOS's lsof does not report whether a unix socket is listening, so that is left unknown. " +
        "Unnamed socket pairs and anonymous pipes are left out.")]
    public async Task<NamedPipesResult> NamedPipes(
        [Description("Match this text anywhere in the socket or FIFO name, for example a product or service name")] string? nameFilter = null,
        CancellationToken cancellationToken = default)
    {
        var result = await pipes.ListAsync(nameFilter, cancellationToken).ConfigureAwait(false);
        return new NamedPipesResult(RenderPipes(result), result.Pipes, result.TotalMatched, result.Truncated, result.Limitations);
    }

    internal static string RenderEndpoints(NetworkEndpoints result)
    {
        var builder = new StringBuilder();
        builder.Append(result.TotalMatched).AppendLine(result.TotalMatched == 1 ? " endpoint" : " endpoints");
        foreach (var endpoint in result.Endpoints.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(endpoint.Protocol).Append(' ').Append(Format(endpoint.LocalAddress, endpoint.LocalPort));
            if (endpoint.RemoteAddress is { } remote && endpoint.RemotePort is { } remotePort)
            {
                builder.Append(" -> ").Append(Format(remote, remotePort));
            }

            if (endpoint.State is { } state)
            {
                builder.Append(' ').Append(RenderLimits.Printable(state));
            }

            builder.Append(": ").AppendLine(RenderLimits.Join(endpoint.Owners
                .Select(o => $"{RenderLimits.Printable(o.ProcessName)} [{o.ProcessId}]").ToList()));
        }

        Tail(builder, result.Endpoints.Count, result.TotalMatched, result.Truncated, "endpoints", result.Limitations);
        return builder.ToString().TrimEnd();
    }

    internal static string RenderPipes(NamedPipeList result)
    {
        var builder = new StringBuilder();
        builder.Append(result.TotalMatched).AppendLine(result.TotalMatched == 1 ? " named socket or FIFO" : " named sockets and FIFOs");
        foreach (var pipe in result.Pipes.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(RenderLimits.Printable(pipe.Name)).Append(" (").Append(RenderLimits.Printable(pipe.Kind))
                .Append(", ").Append(pipe.ConnectedCount).Append(pipe.ConnectedCount == 1 ? " descriptor): " : " descriptors): ")
                .AppendLine(RenderLimits.Join(pipe.Owners.Select(o => $"{RenderLimits.Printable(o.ProcessName)} [{o.ProcessId}]").ToList()));
        }

        Tail(builder, result.Pipes.Count, result.TotalMatched, result.Truncated, "names", result.Limitations);
        return builder.ToString().TrimEnd();
    }

    private static void Tail(StringBuilder builder, int shown, int total, bool truncated, string noun, IReadOnlyList<string> limitations)
    {
        RenderLimits.NoteElision(builder, shown, noun);
        if (truncated)
        {
            builder.Append("Showing the first ").Append(shown).Append(" of ").Append(total).AppendLine("; narrow the filter or raise MACDIAG_MAX_RESULTS.");
        }

        foreach (var limitation in limitations)
        {
            builder.Append("NOTE: ").AppendLine(RenderLimits.Printable(limitation));
        }
    }

    private static string Format(string address, int port) =>
        RenderLimits.Printable(address.Contains(':', StringComparison.Ordinal) ? $"[{address}]:{port}" : $"{address}:{port}");
}
