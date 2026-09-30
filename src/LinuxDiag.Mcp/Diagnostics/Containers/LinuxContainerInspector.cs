using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Diagnostics.Containers;

public sealed class LinuxContainerInspector : IContainerInspector
{
    private readonly DockerEngineClient _docker;

    public LinuxContainerInspector()
        : this(new DockerEngineClient())
    {
    }

    internal LinuxContainerInspector(DockerEngineClient docker) => _docker = docker;

    public async Task<ContainerCatalog> ListAsync(ProcessTable processes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(processes);

        var (docker, dockerLimitation) = await _docker.ListAsync(cancellationToken).ConfigureAwait(false);
        var (tasks, containerdLimitation) = ContainerdTasks.Read();

        var limitations = new List<string>();
        if (dockerLimitation is not null)
        {
            limitations.Add(dockerLimitation);
        }

        if (containerdLimitation is not null)
        {
            limitations.Add(containerdLimitation);
        }

        return new ContainerCatalog(Join(docker, tasks, processes), limitations);
    }

    /// <summary>Both runtimes' containers, deduplicated by id, each with its main PID from the process table.</summary>
    /// <remarks>
    /// The main PID is the process in that container's cgroup whose innermost PID is 1 -- what the
    /// container calls init -- taken from the walk already made, instead of a per-container inspect call
    /// that a hung daemon would block. containerd's init.pid is the fallback.
    /// </remarks>
    internal static List<ContainerInfo> Join(
        IReadOnlyList<DockerContainer> docker, IReadOnlyList<ContainerdTaskEntry> tasks, ProcessTable processes)
    {
        var inits = processes.Processes
            .Where(p => p.Container is not null && p.InnermostProcessId == 1)
            .GroupBy(p => p.Container!.Id, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Min(p => p.ProcessId), StringComparer.Ordinal);

        var members = processes.Processes
            .Where(p => p.Container is not null)
            .GroupBy(p => p.Container!.Id, StringComparer.Ordinal)
            .ToDictionary(
                g => g.Key, g => (IReadOnlyList<int>)g.Select(p => p.ProcessId).Order().ToList(), StringComparer.Ordinal);

        int? MainPid(string id, int? fallback) => inits.TryGetValue(id, out var pid) ? pid : fallback;
        IReadOnlyList<int> Members(string id) => members.GetValueOrDefault(id) ?? [];

        var containers = docker
            .Select(d => new ContainerInfo(
                "docker", d.Id, d.Name, d.Image, d.State, MainPid(d.Id, null), Members(d.Id), null, null, false))
            .ToList();
        var seen = containers.Select(c => c.Id).ToHashSet(StringComparer.Ordinal);

        // A containerd task exists only while it runs; its directory goes when it stops.
        containers.AddRange(tasks
            .Where(t => seen.Add(t.Id))
            .Select(t => new ContainerInfo(
                "containerd", t.Id, t.Name, t.Image, "running", MainPid(t.Id, t.InitProcessId), Members(t.Id),
                t.PodName, t.PodNamespace, t.Sandbox)));

        return containers.OrderBy(c => c.Name ?? c.Id, StringComparer.Ordinal).ToList();
    }
}
