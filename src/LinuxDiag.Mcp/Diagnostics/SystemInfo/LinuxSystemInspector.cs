using System.Runtime.InteropServices;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Linux.Proc;

namespace LinuxDiag.Mcp.Diagnostics.SystemInfo;

public sealed class LinuxSystemInspector(IPrivilegeProbe privileges) : ISystemInspector
{
    public SystemOverview Describe()
    {
        var uptime = Uptime.Parse(ProcFiles.Read(ProcFiles.Uptime));
        var (total, available) = Meminfo.Parse(ProcFiles.Read(ProcFiles.Meminfo));

        return new SystemOverview(
            MachineName: Environment.MachineName,
            UserName: Environment.UserName,
            OperatingSystem: OsRelease.PrettyName(File.Exists(ProcFiles.OsRelease) ? ProcFiles.Read(ProcFiles.OsRelease) : string.Empty),
            // The running kernel's release, read directly: RuntimeInformation.OSDescription returns the
            // distribution's name on Linux, so the summary printed "Ubuntu 24.04.4 LTS" twice.
            Kernel: "Linux " + ProcFiles.Read(ProcFiles.KernelRelease).Trim(),
            Architecture: RuntimeInformation.OSArchitecture.ToString(),
            Elevated: privileges.IsElevated,
            BootTime: DateTimeOffset.UtcNow - uptime,
            Uptime: uptime,
            ProcessorCount: Environment.ProcessorCount,
            TotalPhysicalMemoryBytes: total,
            AvailablePhysicalMemoryBytes: available,
            Filesystems: Filesystems());
    }

    /// <summary>How long one mount may take to report its size before it is listed as not answering.</summary>
    private static readonly TimeSpan PerMountBudget = TimeSpan.FromSeconds(3);

    private static List<MountedFilesystem> Filesystems() =>
        Filesystems(
            Mounts.Parse(ProcFiles.Read(ProcFiles.Mounts)).Where(Mounts.IsDiskLike),
            mountPoint =>
            {
                var drive = new DriveInfo(mountPoint);
                return (drive.TotalSize, drive.AvailableFreeSpace);
            },
            PerMountBudget);

    /// <summary>Each mount's size, bounded per mount.</summary>
    /// <remarks>
    /// statvfs on a hard NFS mount whose server has gone does not fail -- it blocks, uninterruptibly. Asked
    /// inline, one such mount hung the whole call, and update_self waits for in-flight calls, so it held
    /// up an update too. A stale mount is exactly what someone may be here to find, so it is listed as not
    /// answering instead. The probe that timed out is left blocked: nothing can cancel a thread stuck in
    /// the kernel, and one parked thread is the lesser cost.
    /// </remarks>
    internal static List<MountedFilesystem> Filesystems(
        IEnumerable<MountEntry> mounts, Func<string, (long Total, long Free)> size, TimeSpan perMount)
    {
        var result = new List<MountedFilesystem>();
        // The last entry per mount point: a later mount on the same path hides the earlier one, so it is
        // what a process actually sees there. Kept in first-seen order for a stable listing.
        var visible = mounts.GroupBy(m => m.MountPoint, StringComparer.Ordinal).Select(g => g.Last());
        foreach (var mount in visible)
        {
            long totalBytes = 0, freeBytes = 0;
            // A thread of its own, not the pool's: a probe stuck in the kernel keeps its thread for good, and on a
            // small, busy pool the next mount's probe then waited for a thread longer than its whole budget, so a
            // healthy mount was reported as not answering (seen on a two-core CI runner).
            var probe = Task.Factory.StartNew(
                () => size(mount.MountPoint), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            try
            {
                if (probe.Wait(perMount))
                {
                    (totalBytes, freeBytes) = probe.Result;
                }
            }
            catch (AggregateException ex) when (ex.InnerException is IOException or UnauthorizedAccessException)
            {
                // Unreadable: listed with unknown size rather than hidden, like one that did not answer.
            }

            result.Add(new MountedFilesystem(mount.MountPoint, mount.Device, mount.FileSystem, totalBytes, freeBytes, mount.ReadOnly));
        }

        return result;
    }
}
