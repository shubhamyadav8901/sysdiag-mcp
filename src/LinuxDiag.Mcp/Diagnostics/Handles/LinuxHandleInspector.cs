using System.Globalization;
using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Linux.Native;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Linux.Proc;

namespace LinuxDiag.Mcp.Diagnostics.Handles;

public sealed class LinuxHandleInspector(IProcessTable processes, IPrivilegeProbe privileges, LinuxDiagOptions options)
    : IHandleInspector
{
    /// <summary>Who owns what, and which mount namespace this server's own paths belong to.</summary>
    private sealed record Context(IReadOnlyDictionary<long, string> Users, string? SelfMountNamespace);

    public HandleSearch ForProcess(int processId, bool includeAllObjectTypes, CancellationToken cancellationToken)
    {
        if (processId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(processId), "A process id must be positive. Get one from process_list.");
        }

        var table = processes.Read(cancellationToken);
        var process = table.Processes.FirstOrDefault(p => p.ProcessId == processId)
            ?? throw new HandleQueryException(NotRunning(processId));

        IReadOnlyList<(int Descriptor, string Target)>? descriptors;
        try
        {
            descriptors = ProcFiles.Descriptors(processId);
        }
        catch (UnauthorizedAccessException)
        {
            throw new HandleQueryException(
                $"Could not read the open files of {process.Name} (PID {processId}): permission denied. Reading " +
                "another user's process needs root.");
        }

        if (descriptors is null)
        {
            throw new HandleQueryException(
                $"{process.Name} (PID {processId}) exited before its open files could be read. Call process_list for a current PID.");
        }

        var context = ContextFor(table);
        var entries = new List<HandleEntry>();
        foreach (var (fd, target) in descriptors.OrderBy(d => d.Descriptor))
        {
            var type = Classify(processId, fd, target);
            if (includeAllObjectTypes || IsFileReference(type))
            {
                entries.Add(Entry(process, type, fd.ToString(CultureInfo.InvariantCulture), target, AccessOf(processId, fd), context));
            }
        }

        entries.AddRange(Mapped(process, context));
        return Capped($"PID {processId}", entries, table.Unreadable, includeAllObjectTypes, processScoped: true);
    }

    internal static string NotRunning(int processId) =>
        $"No process with PID {processId} is running. Call process_list for a current one; PIDs are reused.";

    internal static bool IsFileReference(string type) => type is "File" or "Directory" or "Mapped";

    /// <summary>The descriptor's kind, telling a directory from a file by the open file's own mode.</summary>
    internal static string Classify(int pid, int fd, string target)
    {
        var kind = DescriptorTarget.Kind(target);
        return kind == "File" && !DescriptorTarget.IsDeleted(target) && LibC.Supported &&
               TryIdentify(ProcFiles.Of(pid, "fd/" + fd.ToString(CultureInfo.InvariantCulture))) is { IsDirectory: true }
            ? "Directory"
            : kind;
    }

    internal static string? AccessOf(int pid, int fd)
    {
        try
        {
            return ProcFiles.ReadProcess(pid, "fdinfo/" + fd.ToString(CultureInfo.InvariantCulture)) is { } text
                ? FdInfo.Parse(text).Access
                : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException)
        {
            return null;
        }
    }

    private HandleSearch Capped(string query, List<HandleEntry> entries, int unreadable, bool includeAll, bool processScoped) =>
        new(query, entries.Take(options.MaxResults).ToList(), privileges.IsElevated, entries.Count > options.MaxResults,
            entries.Count, unreadable, includeAll, processScoped);

    private static Context ContextFor(ProcessTable table)
    {
        IReadOnlyDictionary<long, string> users;
        try
        {
            users = Passwd.Parse(ProcFiles.Read(ProcFiles.Passwd));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            users = new Dictionary<long, string>();
        }

        var self = table.Processes.FirstOrDefault(p => p.ProcessId == Environment.ProcessId)?.MountNamespace;
        return new Context(users, self);
    }

    private static HandleEntry Entry(
        ProcessRecord process, string type, string handleValue, string name, string? access, Context context) =>
        new(process.Name, process.ProcessId, type,
            process.UserId is { } uid && context.Users.TryGetValue(uid, out var user) ? user : null,
            process.UserId, handleValue, name, access,
            context.SelfMountNamespace is not null && process.MountNamespace is not null &&
            process.MountNamespace != context.SelfMountNamespace);

    /// <summary>The files a process has mapped: a holder that only mapped a file still holds it.</summary>
    private static IEnumerable<HandleEntry> Mapped(ProcessRecord process, Context context)
    {
        string? maps;
        try
        {
            maps = ProcFiles.ReadProcess(process.ProcessId, "maps");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return [];
        }

        return maps is null
            ? []
            : ProcMaps.Files(ProcMaps.Parse(maps)).Select(file => Entry(
                process, "Mapped", "mmap", file.Deleted ? file.Path + DescriptorTarget.DeletedSuffix : file.Path,
                file.Writable ? "read-write" : "read", context));
    }

    public HandleSearch Search(string nameFragment, bool includeAllObjectTypes, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nameFragment);

        var table = processes.Read(cancellationToken);
        var walk = DescriptorWalk.All(table, cancellationToken);
        var context = ContextFor(table);

        // An existing path is also matched by what it is, not only by how it is spelled: a container's
        // process names the same file by its own mount namespace's path, and a hard link or a rename gives
        // it another name entirely.
        var identity = Path.IsPathRooted(nameFragment) && LibC.Supported ? TryIdentify(nameFragment) : null;

        var entries = new List<HandleEntry>();
        foreach (var descriptor in walk.Descriptors)
        {
            var isFile = DescriptorTarget.Kind(descriptor.Target) == "File";
            if (!includeAllObjectTypes && !isFile)
            {
                continue;
            }

            var matches = descriptor.Target.Contains(nameFragment, StringComparison.OrdinalIgnoreCase) ||
                          (identity is not null && isFile && TryIdentify(descriptor.LinkPath) == identity);
            if (matches)
            {
                var pid = descriptor.Process.ProcessId;
                entries.Add(Entry(
                    descriptor.Process, Classify(pid, descriptor.Descriptor, descriptor.Target),
                    descriptor.Descriptor.ToString(CultureInfo.InvariantCulture), descriptor.Target,
                    AccessOf(pid, descriptor.Descriptor), context));
            }
        }

        foreach (var process in table.Processes.Where(p => !p.KernelThread))
        {
            cancellationToken.ThrowIfCancellationRequested();
            entries.AddRange(Mapped(process, context)
                .Where(e => e.Name.Contains(nameFragment, StringComparison.OrdinalIgnoreCase)));
        }

        var ordered = entries.OrderBy(e => e.ProcessName, StringComparer.Ordinal).ThenBy(e => e.ProcessId).ToList();
        return Capped(nameFragment, ordered, walk.UnreadableProcesses, includeAllObjectTypes, processScoped: false);
    }

    internal static FileIdentity? TryIdentify(string path)
    {
        try
        {
            return LibC.Identify(path);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }
}
