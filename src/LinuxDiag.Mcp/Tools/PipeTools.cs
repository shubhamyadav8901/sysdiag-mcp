using System.ComponentModel;
using System.Text;
using LinuxDiag.Mcp.Diagnostics.Network;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

/// <summary>Structured result of <c>named_pipes</c>.</summary>
public sealed record NamedPipesResult(
    string Summary, IReadOnlyList<NamedPipe> Pipes, int TotalMatched, bool Truncated, IReadOnlyList<string> Limitations);

[McpServerToolType]
public sealed class PipeTools(IPipeInspector pipes)
{
    [McpServerTool(
        Name = "named_pipes",
        Title = "Named sockets and FIFOs",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "List named unix sockets - filesystem paths and abstract '@' names - and named FIFOs, with whether each " +
        "socket is listening, how many connections it holds, and which processes hold it. Use it when a client " +
        "cannot connect to a local service over its socket: a name nobody is listening on, or a listener owned by " +
        "an unexpected process, shows up here. Listening sockets come first. Unnamed socket pairs are left out; a " +
        "container's sockets are included, their paths as the container sees them.")]
    public NamedPipesResult NamedPipes(
        [Description("Match this text anywhere in the socket or FIFO name, for example a product or service name")] string? nameFilter = null,
        CancellationToken cancellationToken = default)
    {
        var result = pipes.List(nameFilter, cancellationToken);
        return new NamedPipesResult(RenderPipes(result, nameFilter), result.Pipes, result.TotalMatched, result.Truncated, result.Limitations);
    }

    internal static string RenderPipes(NamedPipeList result, string? nameFilter)
    {
        var builder = new StringBuilder();
        foreach (var limitation in result.Limitations)
        {
            builder.Append("WARNING: ").AppendLine(limitation);
        }

        if (result.Pipes.Count == 0)
        {
            builder.Append("No named socket or FIFO matched");
            if (!string.IsNullOrWhiteSpace(nameFilter))
            {
                builder.Append(" '").Append(nameFilter).Append('\'');
            }

            return builder.Append('.').ToString();
        }

        builder.Append(result.TotalMatched).Append(result.TotalMatched == 1 ? " named socket or FIFO" : " named sockets and FIFOs")
            .AppendLine(":");
        foreach (var pipe in result.Pipes.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(pipe.Name).Append(" (").Append(pipe.Kind);
            if (pipe.Listening)
            {
                builder.Append(", listening");
            }

            if (pipe.ConnectedCount > 0)
            {
                builder.Append(", ").Append(pipe.ConnectedCount).Append(pipe.Kind == "Fifo" ? " open" : " connected");
            }

            builder.Append(')');
            builder.Append(pipe.Owners.Count == 0 ? " holder unknown" : " held by ")
                .Append(string.Join(", ", pipe.Owners.Take(3).Select(o => $"{o.ProcessName} (PID {o.ProcessId})")));
            if (pipe.Owners.Count > 3)
            {
                builder.Append(" and ").Append(pipe.Owners.Count - 3).Append(" more");
            }

            if (pipe.OtherMountNamespace)
            {
                builder.Append(" (a path in its holder's own mount namespace)");
            }

            builder.AppendLine();
        }

        RenderLimits.NoteElision(builder, result.Pipes.Count, "returned names");
        if (result.Truncated)
        {
            builder.Append("Showing the first ").Append(result.Pipes.Count).Append(" of ").Append(result.TotalMatched)
                .Append("; narrow the filter or raise LINUXDIAG_MAX_RESULTS.");
        }

        return builder.ToString().TrimEnd();
    }
}
