using LinuxDiag.Mcp.Diagnostics.Processes;

namespace LinuxDiag.Mcp.Diagnostics.Containers;

/// <param name="MainProcessId">The container's init as the host numbers it; null when it shares the host's PID namespace.</param>
/// <param name="ProcessIds">Every host PID in the container's cgroup: spec L2's "every container with its host PIDs".</param>
public sealed record ContainerInfo(
    string Runtime, string Id, string? Name, string? Image, string? State, int? MainProcessId,
    IReadOnlyList<int> ProcessIds, string? PodName, string? PodNamespace, bool Sandbox);

/// <param name="Limitations">Runtimes that exist but could not be asked, so an empty list is never read as "none".</param>
public sealed record ContainerCatalog(IReadOnlyList<ContainerInfo> Containers, IReadOnlyList<string> Limitations);

/// <summary>A process's container, as a process-level result carries it.</summary>
public sealed record ProcessContainer(string Runtime, string Id, string? Name, string? Image, int? ProcessIdInContainer);

public interface IContainerInspector
{
    Task<ContainerCatalog> ListAsync(ProcessTable processes, CancellationToken cancellationToken);
}

public static class ContainerJoin
{
    public static IReadOnlyDictionary<string, ContainerInfo> ById(ContainerCatalog catalog) =>
        catalog.Containers.ToDictionary(c => c.Id, StringComparer.Ordinal);

    /// <summary>The process's container: named when the catalog knows it, else as its cgroup names it.</summary>
    public static ProcessContainer? For(ProcessRecord process, IReadOnlyDictionary<string, ContainerInfo> byId)
    {
        if (process.Container is not { } reference)
        {
            return null;
        }

        return byId.TryGetValue(reference.Id, out var known)
            ? new ProcessContainer(known.Runtime, known.Id, known.Name, known.Image, process.InnermostProcessId)
            : new ProcessContainer(reference.Runtime, reference.Id, null, null, process.InnermostProcessId);
    }
}
