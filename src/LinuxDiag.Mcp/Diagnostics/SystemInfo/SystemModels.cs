namespace LinuxDiag.Mcp.Diagnostics.SystemInfo;

/// <summary>One mounted filesystem with real capacity.</summary>
public sealed record MountedFilesystem(
    string MountPoint,
    string Device,
    string FileSystem,
    long TotalBytes,
    long FreeBytes,
    bool ReadOnly)
{
    public double? PercentFree => TotalBytes > 0 ? Math.Round(100.0 * FreeBytes / TotalBytes, 1) : null;

    /// <summary>A read-only filesystem is always "full"; flagging it teaches the reader to ignore the flag.</summary>
    public bool CanRunOutOfSpace => !ReadOnly;
}

/// <summary>Baseline description of this Linux machine: the first call in an investigation.</summary>
public sealed record SystemOverview(
    string MachineName,
    string UserName,
    string OperatingSystem,
    string Kernel,
    string Architecture,
    bool Elevated,
    DateTimeOffset BootTime,
    TimeSpan Uptime,
    int ProcessorCount,
    long TotalPhysicalMemoryBytes,
    long AvailablePhysicalMemoryBytes,
    IReadOnlyList<MountedFilesystem> Filesystems);

public interface ISystemInspector
{
    SystemOverview Describe();
}
