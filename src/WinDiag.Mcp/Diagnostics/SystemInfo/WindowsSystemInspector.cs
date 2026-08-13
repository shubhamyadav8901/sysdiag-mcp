using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace WinDiag.Mcp.Diagnostics.SystemInfo;

/// <inheritdoc />
[SupportedOSPlatform("windows")]
public sealed class WindowsSystemInspector : ISystemInspector
{
    private readonly IPrivilegeProbe _privileges;

    public WindowsSystemInspector(IPrivilegeProbe privileges)
    {
        _privileges = privileges;
    }

    public SystemOverview Describe()
    {
        var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);
        var (total, available) = ReadPhysicalMemory();

        return new SystemOverview(
            MachineName: Environment.MachineName,
            UserName: $@"{Environment.UserDomainName}\{Environment.UserName}",
            OperatingSystem: RuntimeInformation.OSDescription,
            Architecture: RuntimeInformation.OSArchitecture.ToString(),
            Is64BitOperatingSystem: Environment.Is64BitOperatingSystem,
            Is64BitProcess: Environment.Is64BitProcess,
            Elevated: _privileges.IsElevated,
            BootTime: DateTimeOffset.Now - uptime,
            Uptime: uptime,
            ProcessorCount: Environment.ProcessorCount,
            TotalPhysicalMemoryBytes: total,
            AvailablePhysicalMemoryBytes: available,
            Disks: ReadDisks());
    }

    /// <summary>
    /// Enumerates ready volumes, skipping any that fail.
    /// </summary>
    /// <remarks>
    /// A disconnected network drive or an empty optical drive throws on property access. Letting that
    /// bubble would fail the whole overview because of a drive nobody asked about.
    /// </remarks>
    private static List<LogicalDisk> ReadDisks()
    {
        var disks = new List<LogicalDisk>();

        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (!drive.IsReady)
                {
                    continue;
                }

                disks.Add(new LogicalDisk(
                    Name: drive.Name,
                    Label: string.IsNullOrWhiteSpace(drive.VolumeLabel) ? null : drive.VolumeLabel,
                    FileSystem: drive.DriveFormat,
                    TotalBytes: drive.TotalSize,
                    FreeBytes: drive.AvailableFreeSpace,
                    DriveType: drive.DriveType.ToString()));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Unreachable network share or a drive we cannot query. Skip it.
            }
        }

        return disks;
    }

    private static (long Total, long Available) ReadPhysicalMemory()
    {
        var status = new MemoryStatusEx { dwLength = (uint)Marshal.SizeOf<MemoryStatusEx>() };

        return GlobalMemoryStatusEx(ref status)
            ? ((long)status.ullTotalPhys, (long)status.ullAvailPhys)
            : (0, 0);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatusEx
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx lpBuffer);
}
