using System.Globalization;
using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Linux.Native;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Linux.Proc;

namespace LinuxDiag.Mcp.Diagnostics.Handles;

public sealed class LinuxLockInspector(IProcessTable processes, IPrivilegeProbe privileges) : ILockInspector
{
    /// <summary>The init PID namespace's inode: a fixed kernel constant (PROC_PID_INIT_INO).</summary>
    private const string InitialPidNamespace = "pid:[4026531836]";

    /// <summary>Per-process links that pin a file without an open descriptor.</summary>
    private static readonly (string Link, LockHolderKind Kind)[] ProcessLinks =
        [("exe", LockHolderKind.Executing), ("cwd", LockHolderKind.WorkingDirectory), ("root", LockHolderKind.RootDirectory)];

    /// <summary>A lock as /proc/locks and an fdinfo lock: line both print it, so one can confirm the other.</summary>
    private readonly record struct LockKey(string Type, string Access, int ProcessId, uint DeviceMajor, uint DeviceMinor, long Inode)
    {
        public static LockKey Of(LockEntry entry) =>
            new(entry.Type, entry.Access, entry.ProcessId, entry.DeviceMajor, entry.DeviceMinor, entry.Inode);
    }

    public LockQuery Query(string fullPath, CancellationToken cancellationToken)
    {
        FileIdentity? identity;
        try
        {
            identity = LibC.Identify(fullPath);
        }
        catch (UnauthorizedAccessException)
        {
            // Not "does not exist": that would send the caller away from a path that is there.
            throw new HandleQueryException(
                $"Cannot look up '{fullPath}': permission denied on it or on a directory above it. Run the server as root.");
        }

        if (identity is not { } target)
        {
            return new LockQuery(fullPath, false, [], false, []);
        }

        var table = processes.Read(cancellationToken);
        var walk = DescriptorWalk.All(table, cancellationToken);
        var holders = new List<LockHolder>();
        var fdLocks = new HashSet<LockKey>();
        var limitations = new List<string>();

        // Holders by what they have open: the file's device and inode through each descriptor, so a
        // rename, a hard link or a container's path still matches; locks from that very open file.
        foreach (var descriptor in walk.Descriptors)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (DescriptorTarget.Kind(descriptor.Target) is not ("File" or "Device") ||
                LinuxHandleInspector.TryIdentify(descriptor.LinkPath) is not { } held || !Same(held, target))
            {
                continue;
            }

            var info = FdInfoOf(descriptor);
            var locks = info?.Locks.Select(ProcLocks.ParseLine).ToList() ?? [];
            if (locks.Count == 0)
            {
                holders.Add(Holder(descriptor.Process, LockHolderKind.Open, info?.Access, waiting: false, confirmed: true));
            }

            foreach (var entry in locks)
            {
                holders.Add(Holder(descriptor.Process, KindOf(entry.Type), entry.Access.ToLowerInvariant(), entry.Waiting, confirmed: true));
                fdLocks.Add(LockKey.Of(entry));
            }
        }

        // A file can be held with no descriptor at all: run (the "text file busy" case), mapped, or used as
        // a working or root directory.
        foreach (var process in table.Processes.Where(p => !p.KernelThread))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var executing = false;
            foreach (var (link, kind) in ProcessLinks)
            {
                if (LinuxHandleInspector.TryIdentify(ProcFiles.Of(process.ProcessId, link)) is { } pinned && Same(pinned, target))
                {
                    holders.Add(Holder(process, kind, null, waiting: false, confirmed: true));
                    executing |= kind == LockHolderKind.Executing;
                }
            }

            if (!executing && Maps(process, target))
            {
                holders.Add(Holder(process, LockHolderKind.Mapped, null, waiting: false, confirmed: true));
            }
        }

        var (deviceMismatch, skipped) = AddFromProcLocks(target, table, fdLocks, holders);
        if (skipped > 0)
        {
            limitations.Add($"{skipped} lines of /proc/locks could not be read and were left out.");
        }

        var exhaustive = privileges.IsElevated && walk.UnreadableProcesses == 0 && !deviceMismatch;
        if (walk.UnreadableProcesses > 0)
        {
            limitations.Add($"{walk.UnreadableProcesses} processes could not be read, so holders among them are missing; run the server as root.");
        }
        else if (!privileges.IsElevated)
        {
            limitations.Add("The server is not running as root, so this cannot be called exhaustive.");
        }

        if (ProcFiles.ReadProcessLink(Environment.ProcessId, "ns/pid") != InitialPidNamespace)
        {
            exhaustive = false;
            limitations.Add("The server runs inside a PID namespace - a container - so it sees only that namespace's processes.");
        }

        if (deviceMismatch)
        {
            limitations.Add(
                "/proc/locks names this inode on a different device number - usual on btrfs subvolumes - so those " +
                "entries were matched by inode alone and may belong to another file with the same inode number.");
        }

        var ordered = holders.OrderBy(h => h.Waiting).ThenBy(h => h.ProcessId).ToList();
        return new LockQuery(fullPath, true, ordered, exhaustive, limitations);
    }

    /// <summary>Waiters, and locks no open file confirmed, from /proc/locks: whether a device number disagreed, and lines skipped.</summary>
    private static (bool Mismatch, int Skipped) AddFromProcLocks(
        FileIdentity target, ProcessTable table, HashSet<LockKey> fdLocks, List<LockHolder> holders)
    {
        var byPid = table.Processes.ToDictionary(p => p.ProcessId);
        var mismatch = false;
        var (entries, skipped) = ProcLocks.ParseLenient(ProcFiles.Read(ProcFiles.Locks));
        foreach (var entry in entries.Where(e => (ulong)e.Inode == target.Inode))
        {
            if (entry.DeviceMajor != target.DeviceMajor || entry.DeviceMinor != target.DeviceMinor)
            {
                mismatch = true;
            }

            var kind = KindOf(entry.Type);
            if (entry.Waiting)
            {
                // A waiter's PID is the blocked process itself, so it needs no confirmation.
                holders.Add(byPid.TryGetValue(entry.ProcessId, out var waiter)
                    ? Holder(waiter, kind, entry.Access.ToLowerInvariant(), waiting: true, confirmed: true)
                    : Unlisted(entry, kind, LiveName));
                continue;
            }

            // Confirmed only by the very lock seen through an open file: same type, access, creator and file.
            // Matching on kind alone let one confirmed shared flock hide every other holder's.
            if (!fdLocks.Contains(LockKey.Of(entry)))
            {
                holders.Add(byPid.TryGetValue(entry.ProcessId, out var named)
                    ? Holder(named, kind, entry.Access.ToLowerInvariant(), waiting: false, confirmed: false)
                    : Unlisted(entry, kind, LiveName));
            }
        }

        return (mismatch, skipped);
    }

    /// <summary>A /proc/locks entry whose PID the walk did not see.</summary>
    /// <remarks>
    /// Missing from the snapshot is not the same as gone: /proc/locks is read after the walk, so a process that
    /// took or began waiting for the lock in between -- the installer that just started -- is looked up again.
    /// A PID of -1 (an open file description lock) or 0 (a process in another PID namespace) names no process
    /// here at all, which is different again from one that stopped.
    /// </remarks>
    internal static LockHolder Unlisted(LockEntry entry, LockHolderKind kind, Func<int, string?> liveName)
    {
        var access = entry.Access.ToLowerInvariant();
        if (entry.ProcessId <= 0)
        {
            var name = entry.ProcessId == 0
                ? "(a process in another PID namespace)"
                : "(an open file description lock, which names no process)";
            return new LockHolder(entry.ProcessId, name, kind, access, entry.Waiting, Confirmed: false, StartedAt: null, StillRunning: false);
        }

        return liveName(entry.ProcessId) is { } live
            ? new LockHolder(entry.ProcessId, live, kind, access, entry.Waiting, Confirmed: entry.Waiting, StartedAt: null, StillRunning: true)
            : new LockHolder(entry.ProcessId, "(exited)", kind, access, entry.Waiting, Confirmed: false, StartedAt: null, StillRunning: false);
    }

    /// <summary>The process's name now, or null when it has exited.</summary>
    private static string? LiveName(int processId)
    {
        try
        {
            return ProcFiles.ReadProcess(processId, "stat") is { } stat ? ProcStat.Parse(stat).Name : null;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or FormatException)
        {
            return null;
        }
    }

    private static bool Same(FileIdentity a, FileIdentity b) =>
        a.Inode == b.Inode && a.DeviceMajor == b.DeviceMajor && a.DeviceMinor == b.DeviceMinor;

    private static bool Maps(ProcessRecord process, FileIdentity target)
    {
        try
        {
            return ProcFiles.ReadProcess(process.ProcessId, "maps") is { } text &&
                   ProcMaps.Parse(text).Any(e => (ulong)e.Inode == target.Inode &&
                                                 e.DeviceMajor == target.DeviceMajor && e.DeviceMinor == target.DeviceMinor);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or FormatException)
        {
            return false;
        }
    }

    private static LockHolder Holder(ProcessRecord process, LockHolderKind kind, string? access, bool waiting, bool confirmed) =>
        new(process.ProcessId, process.Name, kind, access, waiting, confirmed, process.StartTime, StillRunning: true);

    private static LockHolderKind KindOf(string type) => type switch
    {
        "FLOCK" => LockHolderKind.Flock,
        "POSIX" => LockHolderKind.Posix,
        "OFDLCK" => LockHolderKind.OpenFileDescription,
        "LEASE" => LockHolderKind.Lease,
        "DELEG" => LockHolderKind.Delegation,
        _ => LockHolderKind.Other,
    };

    private static FdInfoEntry? FdInfoOf(OpenDescriptor descriptor)
    {
        try
        {
            return ProcFiles.ReadProcess(
                descriptor.Process.ProcessId,
                "fdinfo/" + descriptor.Descriptor.ToString(CultureInfo.InvariantCulture)) is { } text
                ? FdInfo.Parse(text)
                : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException)
        {
            return null;
        }
    }
}
