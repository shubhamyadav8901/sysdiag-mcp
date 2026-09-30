using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Diagnostics.Containers;
using LinuxDiag.Mcp.Diagnostics.Handles;
using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Linux.Native;
using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Diagnostics.Network;

public sealed class LinuxPipeInspector(IProcessTable processes, LinuxDiagOptions options) : IPipeInspector
{
    public NamedPipeList List(string? nameFilter, CancellationToken cancellationToken)
    {
        var table = processes.Read(cancellationToken);
        var walk = DescriptorWalk.All(table, cancellationToken);
        var holders = SocketOwners.ByInode(walk, new Dictionary<string, ContainerInfo>());
        var byPid = table.Processes.ToDictionary(p => p.ProcessId);
        var selfMount = byPid.GetValueOrDefault(Environment.ProcessId)?.MountNamespace;

        bool Foreign(IEnumerable<int> owners) =>
            selfMount is not null &&
            owners.Any(pid => byPid.GetValueOrDefault(pid)?.MountNamespace is { } mount && mount != selfMount);

        var pipes = new List<NamedPipe>();

        // Unnamed socket pairs are left out: they have no name to connect to, so they cannot be the thing a
        // client fails to reach. Abstract names ('@') are names, and kept.
        var skipped = 0;
        foreach (var (ns, text) in NetworkNamespaces.Read(table, "unix"))
        {
            var (sockets, unreadable) = UnixSockets.ParseLenient(text);
            skipped += unreadable;
            foreach (var group in sockets.Where(s => s.Path is not null).GroupBy(s => (s.Path!, s.Type)))
            {
                var owners = group.SelectMany(s => holders.GetValueOrDefault(s.Inode) ?? []).DistinctBy(o => o.ProcessId).ToList();
                pipes.Add(new NamedPipe(
                    group.Key.Item1, UnixSockets.KindName(group.Key.Type), group.Any(s => s.Listening),
                    group.Count(s => s.State == 3), owners.Select(o => new PipeOwner(o.ProcessId, o.ProcessName)).ToList(),
                    !group.Key.Item1.StartsWith('@') && Foreign(owners.Select(o => o.ProcessId)), ns));
            }
        }

        // Named FIFOs: open descriptors whose file is a FIFO.
        if (LibC.Supported)
        {
            foreach (var group in walk.Descriptors
                         .Where(d => DescriptorTarget.Kind(d.Target) == "File" &&
                                     LinuxHandleInspector.TryIdentify(d.LinkPath) is { IsFifo: true })
                         .GroupBy(d => d.Target, StringComparer.Ordinal))
            {
                var owners = group.Select(d => d.Process).DistinctBy(p => p.ProcessId).ToList();
                pipes.Add(new NamedPipe(
                    group.Key, "Fifo", false, group.Count(), owners.Select(p => new PipeOwner(p.ProcessId, p.Name)).ToList(),
                    Foreign(owners.Select(p => p.ProcessId)), null));
            }
        }

        var matched = pipes
            .Where(p => string.IsNullOrWhiteSpace(nameFilter) || p.Name.Contains(nameFilter, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(p => p.Listening)
            .ThenBy(p => p.Name, StringComparer.Ordinal)
            .ToList();

        var limitations = new List<string>();
        if (walk.UnreadableProcesses > 0)
        {
            limitations.Add($"{walk.UnreadableProcesses} processes could not be read, so sockets and FIFOs they hold " +
                            "are listed without them; run the server as root.");
        }

        if (skipped > 0)
        {
            limitations.Add($"{skipped} lines of /proc/net/unix could not be read - a socket name holding a newline " +
                            "splits its line - and were left out.");
        }
        return new NamedPipeList(matched.Take(options.MaxResults).ToList(), matched.Count, matched.Count > options.MaxResults, limitations);
    }
}
