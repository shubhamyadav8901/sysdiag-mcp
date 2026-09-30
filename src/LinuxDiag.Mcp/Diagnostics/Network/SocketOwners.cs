using LinuxDiag.Mcp.Diagnostics.Containers;
using LinuxDiag.Mcp.Diagnostics.Handles;
using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Linux.Proc;

namespace LinuxDiag.Mcp.Diagnostics.Network;

public static class SocketOwners
{
    /// <summary>Socket inode to every process holding it, from one descriptor walk.</summary>
    public static IReadOnlyDictionary<long, IReadOnlyList<SocketOwner>> ByInode(
        DescriptorSnapshot walk, IReadOnlyDictionary<string, ContainerInfo> containers)
    {
        ArgumentNullException.ThrowIfNull(walk);

        return walk.Descriptors
            .Select(d => (Inode: DescriptorTarget.SocketInode(d.Target), d.Process))
            .Where(d => d.Inode is not null)
            .GroupBy(d => d.Inode!.Value)
            .ToDictionary(
                g => g.Key,
                g => (IReadOnlyList<SocketOwner>)g
                    .DistinctBy(d => d.Process.ProcessId)
                    .Select(d => new SocketOwner(d.Process.ProcessId, d.Process.Name, ContainerJoin.For(d.Process, containers)))
                    .OrderBy(o => o.ProcessId)
                    .ToList());
    }
}

public static class NetworkNamespaces
{
    /// <summary>One /proc/&lt;pid&gt;/net/&lt;file&gt; per network namespace, read through a process inside it.</summary>
    /// <remarks>
    /// A namespace is reached only through a process in it, so one with no process -- kept alive by a bind
    /// mount under /run/netns -- is not visible. Up to three members are tried, since the first may exit.
    /// </remarks>
    public static IEnumerable<(string Namespace, string Text)> Read(ProcessTable table, string file)
    {
        ArgumentNullException.ThrowIfNull(table);

        foreach (var members in table.Processes.Where(p => p.NetworkNamespace is not null)
                     .GroupBy(p => p.NetworkNamespace!, StringComparer.Ordinal))
        {
            foreach (var member in members.Take(3))
            {
                string? text;
                try
                {
                    text = ProcFiles.ReadProcess(member.ProcessId, "net/" + file);
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
                {
                    // tcp6 is absent when IPv6 is disabled, and that is not a namespace to retry.
                    break;
                }

                if (text is not null)
                {
                    yield return (members.Key, text);
                    break;
                }
            }
        }
    }
}
