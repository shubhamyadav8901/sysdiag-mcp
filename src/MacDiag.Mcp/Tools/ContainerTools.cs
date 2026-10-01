using System.ComponentModel;
using System.Text;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Containers;
using ModelContextProtocol.Server;

namespace MacDiag.Mcp.Tools;

/// <summary>Structured result of <c>container_list</c>.</summary>
public sealed record ContainerListResult(
    string Summary, IReadOnlyList<ContainerInfo> Containers, int TotalMatched, bool Truncated, IReadOnlyList<string> Limitations);

[McpServerToolType]
public sealed class ContainerTools(IContainerInspector containers, MacDiagOptions options)
{
    [McpServerTool(
        Name = "container_list",
        Title = "Containers on this Mac",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "List the Docker containers on this Mac - from Docker Desktop, Colima, OrbStack or Rancher Desktop, for " +
        "every user - with each one's name, image, state, and the engine and socket it came from. Containers run " +
        "inside a virtual machine on macOS, so they have no host PIDs and their processes are not in process_list. " +
        "Each engine is asked through its Engine API socket, and only when the socket is owned by its home " +
        "directory's owner in directories no other account can change. A socket that was refused or could not be " +
        "asked is named in Limitations, so an empty list is never mistaken for 'no containers'.")]
    public async Task<ContainerListResult> ContainerList(
        [Description("Only containers whose name, image or id contains this text")] string? nameFilter = null,
        CancellationToken cancellationToken = default)
    {
        var catalog = await containers.ListAsync(cancellationToken).ConfigureAwait(false);
        return Build(catalog.Containers, catalog.Limitations, nameFilter, options.MaxResults);
    }

    /// <summary>The matching containers, capped at the row limit like every other list, with the full count kept.</summary>
    internal static ContainerListResult Build(
        IReadOnlyList<ContainerInfo> all, IReadOnlyList<string> limitations, string? nameFilter, int maxResults)
    {
        var matched = all.Where(c => Matches(c, nameFilter)).ToList();
        var rows = matched.Take(maxResults).ToList();
        return new ContainerListResult(
            RenderContainers(rows, limitations, nameFilter, matched.Count), rows, matched.Count, matched.Count > rows.Count, limitations);
    }

    internal static bool Matches(ContainerInfo container, string? filter) =>
        string.IsNullOrWhiteSpace(filter) ||
        new[] { container.Name, container.Image, container.Id }
            .Any(value => value?.Contains(filter, StringComparison.OrdinalIgnoreCase) == true);

    internal static string ShortId(string id) => id.Length > 12 ? id[..12] : id;

    internal static string RenderContainers(
        IReadOnlyList<ContainerInfo> containers, IReadOnlyList<string> limitations, string? nameFilter, int? totalMatched = null)
    {
        var total = totalMatched ?? containers.Count;
        var builder = new StringBuilder();
        foreach (var limitation in limitations)
        {
            builder.Append("WARNING: ").AppendLine(RenderLimits.Printable(limitation));
        }

        if (containers.Count == 0)
        {
            builder.Append("No container");
            if (!string.IsNullOrWhiteSpace(nameFilter))
            {
                builder.Append(" matching '").Append(RenderLimits.Printable(nameFilter)).Append('\'');
            }

            builder.Append(" was found.");
            if (limitations.Count > 0)
            {
                builder.Append(" The engines above were not or could not be asked, so this is not proof there are none.");
            }

            return builder.ToString().TrimEnd();
        }

        builder.Append(total).Append(total == 1 ? " container" : " containers").AppendLine(":");
        foreach (var container in containers.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(RenderLimits.Printable(container.Name ?? ShortId(container.Id)))
                .Append(" (").Append(RenderLimits.Printable(container.Engine)).Append(' ').Append(RenderLimits.Printable(ShortId(container.Id))).Append(')');
            if (container.Image is not null)
            {
                builder.Append(", image ").Append(RenderLimits.Printable(container.Image));
            }

            if (container.State is not null)
            {
                builder.Append(", ").Append(RenderLimits.Printable(container.State));
            }

            builder.AppendLine();
        }

        RenderLimits.NoteElision(builder, containers.Count, "containers");
        if (total > containers.Count)
        {
            builder.Append("Showing the first ").Append(containers.Count).Append(" of ").Append(total)
                .Append("; narrow with nameFilter or raise MACDIAG_MAX_RESULTS.");
        }

        return builder.ToString().TrimEnd();
    }
}
