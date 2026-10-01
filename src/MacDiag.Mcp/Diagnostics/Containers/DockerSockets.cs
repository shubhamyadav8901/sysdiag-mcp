using MacDiag.Mcp.Hosting;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Containers;

/// <param name="Home">The home directory the socket lives in; null for the system socket, which root must own.</param>
public sealed record DockerSocket(string Path, string Engine, string? Home);

/// <summary>Where Docker Engine sockets live on a Mac, and whether one may be trusted enough to ask.</summary>
/// <remarks>
/// <para>On a Mac every engine runs its daemon in a virtual machine and serves the API on a socket in a user's
/// home. A root server asking such a socket crosses a trust boundary LinuxDiag never had: the user owns it and
/// everything around it. So a socket is asked only when it is a socket, owned by that home's owner (root for the
/// system socket), in directories no other account can change -- otherwise another user could plant a listener
/// of their own where root will talk to it.</para>
/// </remarks>
public static class DockerSockets
{
    public const string SystemSocket = "/var/run/docker.sock";

    /// <summary>A root-owned directory that group daemon can write: /private/var/run, where launchd keeps sockets.</summary>
    private const int DaemonGroup = 1;

    /// <param name="listDirectories">The subdirectories of a directory, as full paths; empty when it does not exist.</param>
    public static IReadOnlyList<DockerSocket> Candidates(IEnumerable<string> homes, Func<string, IEnumerable<string>> listDirectories)
    {
        ArgumentNullException.ThrowIfNull(homes);
        ArgumentNullException.ThrowIfNull(listDirectories);

        var candidates = new List<DockerSocket> { new(SystemSocket, "Docker", null) };
        foreach (var home in homes)
        {
            candidates.Add(new($"{home}/.docker/run/docker.sock", "Docker Desktop", home));
            candidates.Add(new($"{home}/Library/Containers/com.docker.docker/Data/docker.raw.sock", "Docker Desktop (before 4.13)", home));
            candidates.Add(new($"{home}/.orbstack/run/docker.sock", "OrbStack", home));
            candidates.Add(new($"{home}/.rd/docker.sock", "Rancher Desktop", home));
            foreach (var profile in listDirectories($"{home}/.colima").Order(StringComparer.Ordinal))
            {
                candidates.Add(new($"{profile}/docker.sock", $"Colima ({profile[(profile.LastIndexOf('/') + 1)..]})", home));
            }
        }

        return candidates;
    }

    /// <summary>Why the socket must not be asked, or null when it may be.</summary>
    /// <param name="socket">The socket's resolved path: no link in it.</param>
    /// <param name="owners">Who may own the socket and the directories above it, besides root for the directories.</param>
    /// <param name="stats">stat lines for the socket and every directory above it.</param>
    public static string? Problem(string socket, IReadOnlySet<int> owners, IReadOnlyDictionary<string, StatLine> stats)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentNullException.ThrowIfNull(owners);
        ArgumentNullException.ThrowIfNull(stats);

        if (!stats.TryGetValue(socket, out var self))
        {
            return "it could not be checked.";
        }

        if (self.Kind != StatKind.Socket)
        {
            return "it is not a socket.";
        }

        if (!owners.Contains(self.Uid))
        {
            return $"it is owned by uid {self.Uid}, not by {Describe(owners)}.";
        }

        var directoryOwners = new HashSet<int>(owners) { 0 };
        foreach (var directory in StartupPermissions.Chain(socket).SkipLast(1))
        {
            if (!stats.TryGetValue(directory, out var line))
            {
                return $"{directory} above it could not be checked.";
            }

            var trusted = line.Uid == 0 ? new HashSet<int>(StatLines.TrustedGroups) { DaemonGroup } : StatLines.TrustedGroups;
            if (line.Kind != StatKind.Directory || StatLines.WritableByOthers(line, directoryOwners, trusted))
            {
                return $"{directory} above it could be changed by another account (owner uid {line.Uid}, mode {Convert.ToString(line.Mode, 8).PadLeft(4, '0')}), " +
                       "so the socket could be swapped for another listener.";
            }
        }

        return null;
    }

    private static string Describe(IReadOnlySet<int> owners) =>
        owners.Count == 1 && owners.Contains(0) ? "root" : "the home directory's owner (uid " + string.Join(", ", owners.Order()) + ")";
}
