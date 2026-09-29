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
            Kernel: RuntimeInformation.OSDescription,
            Architecture: RuntimeInformation.OSArchitecture.ToString(),
            Elevated: privileges.IsElevated,
            BootTime: DateTimeOffset.UtcNow - uptime,
            Uptime: uptime,
            ProcessorCount: Environment.ProcessorCount,
            TotalPhysicalMemoryBytes: total,
            AvailablePhysicalMemoryBytes: available,
            Filesystems: Filesystems());
    }

    private static List<MountedFilesystem> Filesystems()
    {
        var result = new List<MountedFilesystem>();
        foreach (var mount in Mounts.Parse(ProcFiles.Read(ProcFiles.Mounts)).Where(Mounts.IsDiskLike)
                     .DistinctBy(m => m.MountPoint, StringComparer.Ordinal))
        {
            long totalBytes = 0, freeBytes = 0;
            try
            {
                var drive = new DriveInfo(mount.MountPoint);
                totalBytes = drive.TotalSize;
                freeBytes = drive.AvailableFreeSpace;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A stale network mount or an unreadable one: listed with unknown size rather than hidden,
                // since "the NFS mount is hung" is itself the finding.
            }

            result.Add(new MountedFilesystem(mount.MountPoint, mount.Device, mount.FileSystem, totalBytes, freeBytes, mount.ReadOnly));
        }

        return result;
    }
}
