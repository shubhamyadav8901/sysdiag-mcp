using System.ComponentModel;
using System.Text;
using LinuxDiag.Mcp.Diagnostics.Network;
using LinuxDiag.Mcp.Linux.Parsers;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

/// <summary>Structured result of <c>network_owners</c>.</summary>
public sealed record NetworkOwnersResult(
    string Summary, IReadOnlyList<NetworkEndpoint> Endpoints, int TotalMatched, bool Truncated, IReadOnlyList<string> Limitations);

[McpServerToolType]
public sealed class NetworkTools(INetworkInspector network)
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
        "workers all share one listening socket - and, for a container's process, its container. Every network " +
        "namespace with a running process is covered, so a container's sockets appear too, tagged with their " +
        "namespace. Use it for 'what is already using port 8080', 'which process is talking to that address', or " +
        "to confirm a service is listening where it should be. Filter by port, owning PID, or listening endpoints " +
        "only. A namespace with no process in it (one kept only by /run/netns) is not visible.")]
    public async Task<NetworkOwnersResult> NetworkOwners(
        [Description("Only endpoints using this local or remote port")] int? port = null,
        [Description("Only endpoints owned by this process id")] int? processId = null,
        [Description("Only listening TCP sockets and bound UDP endpoints, excluding established connections")] bool listeningOnly = false,
        CancellationToken cancellationToken = default)
    {
        var result = await network.EndpointsAsync(port, processId, listeningOnly, cancellationToken).ConfigureAwait(false);
        return new NetworkOwnersResult(
            RenderEndpoints(result, port, processId, listeningOnly), result.Endpoints, result.TotalMatched, result.Truncated,
            result.Limitations);
    }

    internal static string RenderEndpoints(NetworkEndpoints result, int? port, int? processId, bool listeningOnly)
    {
        var builder = new StringBuilder();
        foreach (var limitation in result.Limitations)
        {
            builder.Append("WARNING: ").AppendLine(RenderLimits.Printable(limitation));
        }

        if (result.Endpoints.Count == 0)
        {
            builder.Append("No ").Append(listeningOnly ? "listening endpoint" : "endpoint").Append(" matched");
            if (port is not null)
            {
                builder.Append(" port ").Append(port);
            }

            if (processId is not null)
            {
                builder.Append(" PID ").Append(processId);
            }

            builder.Append('.');
            if (port is not null)
            {
                builder.Append(" Nothing is bound to that port, so a bind failure there is not a conflict with another process.");
            }

            return builder.ToString();
        }

        builder.Append(result.TotalMatched).Append(result.TotalMatched == 1 ? " endpoint" : " endpoints").AppendLine(":");
        foreach (var endpoint in result.Endpoints.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(endpoint.Protocol.ToString().ToUpperInvariant()).Append(' ')
                .Append(RenderLimits.Printable(Format(endpoint.LocalAddress, endpoint.LocalPort)));
            if (endpoint.RemoteAddress is not null)
            {
                builder.Append(" -> ").Append(RenderLimits.Printable(Format(endpoint.RemoteAddress, endpoint.RemotePort ?? 0)));
            }

            if (endpoint.State is not null)
            {
                builder.Append(" [").Append(RenderLimits.Printable(endpoint.State)).Append(']');
            }

            builder.Append(endpoint.Owners.Count == 0 ? " owner unknown" : " owned by ")
                .Append(RenderLimits.Printable(string.Join(", ", endpoint.Owners.Take(3).Select(o => $"{o.ProcessName} (PID {o.ProcessId})"))));
            if (endpoint.Owners.Count > 3)
            {
                builder.Append(" and ").Append(endpoint.Owners.Count - 3).Append(" more");
            }

            if (endpoint.Owners.FirstOrDefault(o => o.Container is not null)?.Container is { } container)
            {
                builder.Append(" [").Append(RenderLimits.Printable(container.Runtime)).Append(' ')
                    .Append(RenderLimits.Printable(container.Name ?? ContainerTools.ShortId(container.Id))).Append(']');
            }

            if (endpoint.NetworkNamespace != result.HostNetworkNamespace)
            {
                builder.Append(" [netns ").Append(RenderLimits.Printable(endpoint.NetworkNamespace)).Append(']');
            }

            builder.AppendLine();
        }

        RenderLimits.NoteElision(builder, result.Endpoints.Count, "returned endpoints");
        if (result.Truncated)
        {
            builder.Append("Showing the first ").Append(result.Endpoints.Count).Append(" of ").Append(result.TotalMatched)
                .Append("; narrow the filter or raise LINUXDIAG_MAX_RESULTS.");
        }

        return builder.ToString().TrimEnd();
    }

    private static string Format(string address, int port) =>
        address.Contains(':', StringComparison.Ordinal) ? $"[{address}]:{port}" : $"{address}:{port}";
}
