using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Containers;

/// <param name="Engine">What serves the socket: Docker Desktop, Colima (profile), OrbStack, Rancher Desktop.</param>
/// <param name="MainProcessId">Always null on macOS: containers run inside a virtual machine, not as host processes.</param>
public sealed record ContainerInfo(
    string Runtime, string Engine, string Socket, string Id, string? Name, string? Image, string? State, int? MainProcessId);

/// <param name="Limitations">Engines that exist but were not or could not be asked, so an empty list is never read as "none".</param>
public sealed record ContainerCatalog(IReadOnlyList<ContainerInfo> Containers, IReadOnlyList<string> Limitations);

public interface IContainerInspector
{
    Task<ContainerCatalog> ListAsync(CancellationToken cancellationToken);
}

/// <summary>One question to one Docker Engine socket.</summary>
public interface IDockerQuery
{
    /// <returns>The containers, or none and why.</returns>
    Task<(IReadOnlyList<DockerContainer> Containers, string? Limitation)> QueryAsync(string socketPath, CancellationToken cancellationToken);
}
