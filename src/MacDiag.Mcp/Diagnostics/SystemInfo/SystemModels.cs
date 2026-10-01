namespace MacDiag.Mcp.Diagnostics.SystemInfo;

/// <summary>One volume with real capacity.</summary>
public sealed record MountedFilesystem(
    string MountPoint,
    string Device,
    string FileSystem,
    long TotalBytes,
    long FreeBytes,
    bool ReadOnly)
{
    public double? PercentFree => TotalBytes > 0 ? Math.Round(100.0 * FreeBytes / TotalBytes, 1) : null;

    /// <summary>The sealed system volume is read-only and always nearly "full"; flagging it teaches the reader to ignore the flag.</summary>
    public bool CanRunOutOfSpace => !ReadOnly;
}

/// <summary>Baseline description of this Mac: the first call in an investigation.</summary>
/// <param name="Model">The hardware model identifier (hw.model), e.g. Mac14,2; null when it could not be read.</param>
/// <param name="Limitations">What could not be read, so a missing value is never mistaken for zero.</param>
public sealed record SystemOverview(
    string MachineName,
    string UserName,
    string OperatingSystem,
    string Kernel,
    string Architecture,
    string? Model,
    bool Elevated,
    DateTimeOffset BootTime,
    TimeSpan Uptime,
    int ProcessorCount,
    long TotalPhysicalMemoryBytes,
    long AvailablePhysicalMemoryBytes,
    IReadOnlyList<MountedFilesystem> Filesystems,
    IReadOnlyList<string> Limitations);

public interface ISystemInspector
{
    Task<SystemOverview> DescribeAsync(CancellationToken cancellationToken);
}
