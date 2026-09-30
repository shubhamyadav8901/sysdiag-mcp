using System.ComponentModel;
using System.Text;
using LinuxDiag.Mcp.Diagnostics.Containers;
using LinuxDiag.Mcp.Diagnostics.Processes;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

/// <summary>Structured result of <c>container_list</c>.</summary>
public sealed record ContainerListResult(string Summary, IReadOnlyList<ContainerInfo> Containers, IReadOnlyList<string> Limitations);

[McpServerToolType]
public sealed class ContainerTools(IProcessTable processes, IContainerInspector containers)
{
    [McpServerTool(
        Name = "container_list",
        Title = "Containers on this host",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "List the containers on this host - Docker's, and containerd's including Kubernetes pods - with each " +
        "one's name, image, state and main PID as the host numbers it. Use it to go from a container you know by " +
        "name to the host processes behind it; process_list goes the other way, tagging every process with its " +
        "container. Docker is asked through its Engine API socket and containerd through its task state on disk. " +
        "A runtime this account cannot reach is named in Limitations, so an empty list is never mistaken for 'no " +
        "containers'.")]
    public async Task<ContainerListResult> ContainerList(
        [Description("Only containers whose name, image, pod or id contains this text")] string? nameFilter = null,
        CancellationToken cancellationToken = default)
    {
        var catalog = await containers.ListAsync(processes.Read(cancellationToken), cancellationToken).ConfigureAwait(false);
        var matched = catalog.Containers.Where(c => Matches(c, nameFilter)).ToList();
        return new ContainerListResult(RenderContainers(matched, catalog.Limitations, nameFilter), matched, catalog.Limitations);
    }

    internal static bool Matches(ContainerInfo container, string? filter) =>
        string.IsNullOrWhiteSpace(filter) ||
        new[] { container.Name, container.Image, container.PodName, container.Id }
            .Any(value => value?.Contains(filter, StringComparison.OrdinalIgnoreCase) == true);

    internal static string ShortId(string id) => id.Length > 12 ? id[..12] : id;

    internal static string RenderContainers(
        IReadOnlyList<ContainerInfo> containers, IReadOnlyList<string> limitations, string? nameFilter)
    {
        var builder = new StringBuilder();
        foreach (var limitation in limitations)
        {
            builder.Append("WARNING: ").AppendLine(limitation);
        }

        if (containers.Count == 0)
        {
            builder.Append("No container");
            if (!string.IsNullOrWhiteSpace(nameFilter))
            {
                builder.Append(" matching '").Append(nameFilter).Append('\'');
            }

            builder.Append(" was found.");
            if (limitations.Count > 0)
            {
                builder.Append(" The runtimes above could not be asked, so this is not proof there are none.");
            }

            return builder.ToString().TrimEnd();
        }

        builder.Append(containers.Count).Append(containers.Count == 1 ? " container" : " containers").AppendLine(":");
        foreach (var container in containers.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(container.Name ?? ShortId(container.Id))
                .Append(" (").Append(container.Runtime).Append(' ').Append(ShortId(container.Id)).Append(')');
            if (container.Image is not null)
            {
                builder.Append(", image ").Append(container.Image);
            }

            if (container.State is not null)
            {
                builder.Append(", ").Append(container.State);
            }

            if (container.MainProcessId is { } pid)
            {
                builder.Append(", main PID ").Append(pid);
            }
            else if (container.State == "running")
            {
                builder.Append(", main PID unknown (it shares the host's PID namespace)");
            }

            if (container.ProcessIds.Count > 0)
            {
                builder.Append(", ").Append(container.ProcessIds.Count)
                    .Append(container.ProcessIds.Count == 1 ? " process" : " processes");
            }

            if (container.PodName is not null)
            {
                builder.Append(", pod ").Append(container.PodNamespace).Append('/').Append(container.PodName);
            }

            if (container.Sandbox)
            {
                builder.Append(" [pod sandbox]");
            }

            builder.AppendLine();
        }

        RenderLimits.NoteElision(builder, containers.Count, "containers");
        return builder.ToString().TrimEnd();
    }
}
