using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Hosting;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Containers;

/// <summary>Every Docker Engine on this Mac whose socket checks out, asked for its containers.</summary>
/// <remarks>
/// <para>A socket that is a link is not asked as itself: connect would follow whatever the link says at that
/// moment. Docker Desktop makes /var/run/docker.sock a link into the user's home, so a link whose target is in a
/// home is asked under the target's own path, with the target's own checks; a link anywhere else is refused.</para>
/// <para>Two sockets can lead to one daemon, so containers are kept once by id.</para>
/// </remarks>
public sealed class MacContainerInspector(IExternalCommand commands, MacDiagOptions options, IDockerQuery docker, IPrivilegeProbe privilege) : IContainerInspector
{
    internal const string VirtualMachineNote =
        "Containers run in a virtual machine on macOS, so they have no host PIDs; their processes do not appear in process_list.";

    internal const string NotRootNote =
        "The server is not running as root, so an engine socket in another user's home may be out of its reach and is then not listed.";

    internal Func<IEnumerable<string>> ListHomes { get; init; } = DefaultHomes;

    internal Func<string, IEnumerable<string>> ListDirectories { get; init; } = DefaultDirectories;

    internal Func<string, string> Resolve { get; init; } = StartupPermissions.RealPath;

    public async Task<ContainerCatalog> ListAsync(CancellationToken cancellationToken)
    {
        var limitations = new List<string>();
        var homes = ListHomes().ToList();
        var candidates = new List<DockerSocket>();
        foreach (var candidate in DockerSockets.Candidates(homes, ListDirectories))
        {
            if (StatLines.HasControlCharacter(candidate.Path))
            {
                limitations.Add($"Not asking {Printable(candidate.Path)}: its name contains a control character.");
            }
            else
            {
                candidates.Add(candidate);
            }
        }

        var first = await StatLines.StatAsync(commands, candidates.Select(c => c.Path), options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);

        // What to ask, under its resolved path: present sockets as they are, and links whose target is in a home.
        var accepted = new List<(DockerSocket Socket, string Resolved, bool ViaLink)>();
        foreach (var candidate in candidates.Where(c => first.ContainsKey(c.Path)))
        {
            // A link that loops or cannot be followed is the user's to plant; it costs that socket, not the call.
            string target;
            try
            {
                target = first[candidate.Path].Kind == StatKind.Link ? Resolve(candidate.Path) : ResolveDirectory(candidate.Path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                limitations.Add($"Not asking {candidate.Path}: it could not be resolved ({ex.Message}).");
                continue;
            }

            if (first[candidate.Path].Kind != StatKind.Link)
            {
                accepted.Add((candidate, target, false));
                continue;
            }

            if (HomeOf(target) is { } home && !StatLines.HasControlCharacter(target))
            {
                accepted.Add((candidate with { Path = target, Home = home }, target, true));
            }
            else
            {
                limitations.Add($"Not asking {candidate.Path}: it is a link to {Printable(target)}, outside every home directory.");
            }
        }

        // A socket found where it lives names its engine better than a link that leads to it.
        var unique = accepted
            .OrderBy(a => a.ViaLink)
            .DistinctBy(a => a.Resolved, StringComparer.Ordinal)
            .ToList();
        var second = await StatLines.StatAsync(
                commands,
                unique.SelectMany(a => StartupPermissions.Chain(a.Resolved)).Concat(unique.Select(a => a.Socket.Home).OfType<string>()),
                options.ExternalToolTimeout,
                cancellationToken)
            .ConfigureAwait(false);

        var containers = new Dictionary<string, ContainerInfo>(StringComparer.Ordinal);
        foreach (var (socket, resolved, _) in unique)
        {
            if (!second.ContainsKey(resolved))
            {
                continue; // a link to a socket that is not there: nothing listens
            }

            IReadOnlySet<int> owners = socket.Home is null ? new HashSet<int> { 0 }
                : second.TryGetValue(socket.Home, out var home) ? new HashSet<int> { home.Uid }
                : new HashSet<int>();
            if (DockerSockets.Problem(resolved, owners, second) is { } problem)
            {
                limitations.Add($"Not asking {resolved} ({socket.Engine}): {problem}");
                continue;
            }

            var (found, limitation) = await docker.QueryAsync(resolved, cancellationToken).ConfigureAwait(false);
            if (limitation is not null)
            {
                limitations.Add(limitation);
            }

            foreach (var container in found)
            {
                containers.TryAdd(container.Id, new ContainerInfo("docker", socket.Engine, resolved, container.Id, container.Name, container.Image, container.State, null));
            }
        }

        if (containers.Count > 0)
        {
            limitations.Add(VirtualMachineNote);
        }

        // stat cannot see into a home it may not search, and says so only on stderr: without root, absence is not proof.
        if (!privilege.IsElevated)
        {
            limitations.Add(NotRootNote);
        }

        var rows = containers.Values
            .OrderBy(c => c.Name ?? string.Empty, StringComparer.Ordinal)
            .ThenBy(c => c.Id, StringComparer.Ordinal)
            .ToList();
        return new ContainerCatalog(rows, limitations);
    }

    /// <summary>The socket's path with any link in its directories resolved, so the checks judge the real directories.</summary>
    private string ResolveDirectory(string path)
    {
        var slash = path.LastIndexOf('/');
        return slash <= 0 ? path : Resolve(path[..slash]).TrimEnd('/') + path[slash..];
    }

    /// <summary>/Users/&lt;name&gt; when the path lies inside it.</summary>
    private static string? HomeOf(string path)
    {
        const string Users = "/Users/";
        if (!path.StartsWith(Users, StringComparison.Ordinal))
        {
            return null;
        }

        var end = path.IndexOf('/', Users.Length);
        return end <= Users.Length ? null : path[..end];
    }

    private static string Printable(string text) => string.Concat(text.Select(c => char.IsControl(c) ? '?' : c));

    private static IEnumerable<string> DefaultHomes()
    {
        try
        {
            return Directory.EnumerateDirectories("/Users")
                .Where(d => Path.GetFileName(d) is { Length: > 0 } name && name != "Shared" && !name.StartsWith('.'))
                .ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static IEnumerable<string> DefaultDirectories(string directory)
    {
        try
        {
            return Directory.Exists(directory) ? Directory.EnumerateDirectories(directory).ToList() : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
