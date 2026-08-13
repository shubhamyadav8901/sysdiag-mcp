namespace WinDiag.Mcp.Diagnostics.SystemInfo;

/// <summary>One mounted logical volume.</summary>
public sealed record LogicalDisk(
    string Name,
    string? Label,
    string FileSystem,
    long TotalBytes,
    long FreeBytes,
    string DriveType)
{
    /// <summary>Percentage of the volume still free, or null when the size is unknown.</summary>
    public double? PercentFree => TotalBytes > 0 ? Math.Round(100.0 * FreeBytes / TotalBytes, 1) : null;

    /// <summary>Whether running out of space on this volume would actually mean anything.</summary>
    /// <remarks>
    /// Optical media and mounted ISOs are read-only and therefore always 0% free. Reporting a mounted
    /// Windows installer ISO as "CRITICALLY LOW" is noise that trains the reader to ignore the warning
    /// on the volume where it matters.
    /// </remarks>
    public bool CanRunOutOfSpace => !string.Equals(DriveType, "CDRom", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Baseline description of the machine the server is running on.</summary>
/// <remarks>
/// Intended as the first call in an investigation: it establishes what the box is, whether the server
/// can see everything, and whether obvious environmental causes (a full disk, a recent reboot,
/// exhausted memory) are in play before anything more specific is examined.
/// </remarks>
public sealed record SystemOverview(
    string MachineName,
    string UserName,
    string OperatingSystem,
    string Architecture,
    bool Is64BitOperatingSystem,
    bool Is64BitProcess,
    bool Elevated,
    DateTimeOffset BootTime,
    TimeSpan Uptime,
    int ProcessorCount,
    long TotalPhysicalMemoryBytes,
    long AvailablePhysicalMemoryBytes,
    IReadOnlyList<LogicalDisk> Disks);

/// <summary>Describes the machine the server is running on.</summary>
public interface ISystemInspector
{
    SystemOverview Describe();
}
