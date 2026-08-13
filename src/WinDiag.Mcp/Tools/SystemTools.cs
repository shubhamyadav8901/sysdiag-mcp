using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics.Capabilities;
using WinDiag.Mcp.Diagnostics.SystemInfo;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>system_overview</c>.</summary>
public sealed record SystemOverviewResult(string Summary, SystemOverview System);

/// <summary>Structured result of <c>capabilities</c>.</summary>
public sealed record CapabilitiesResult(
    string Summary,
    bool Elevated,
    IReadOnlyList<ToolCapability> Tools);

/// <summary>Orientation tools: what is this machine, and what can I see on it.</summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class SystemTools
{
    private readonly ISystemInspector _system;
    private readonly ICapabilityReporter _capabilities;

    public SystemTools(ISystemInspector system, ICapabilityReporter capabilities)
    {
        _system = system;
        _capabilities = capabilities;
    }

    [McpServerTool(
        Name = "system_overview",
        Title = "System overview",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Describe the machine: OS build, architecture, uptime and boot time, processor count, physical " +
        "memory, logical disks with free space, the account the server runs as, and whether it is " +
        "elevated. Good first call in any investigation - it establishes the ground truth and surfaces " +
        "environmental causes (a full disk, a very recent reboot, exhausted memory) before you go " +
        "looking for something subtler.")]
    public SystemOverviewResult SystemOverview()
    {
        var overview = _system.Describe();
        return new SystemOverviewResult(RenderOverview(overview), overview);
    }

    [McpServerTool(
        Name = "capabilities",
        Title = "Server capabilities",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Report which of this server's tools can actually answer completely on this machine, and why " +
        "any cannot - a missing Sysinternals binary, or a tool that silently returns partial results " +
        "because the server is not elevated. Call this when a result looks surprisingly empty, before " +
        "concluding that nothing was found.")]
    public CapabilitiesResult Capabilities()
    {
        var capabilities = _capabilities.Describe();
        var overview = _system.Describe();

        return new CapabilitiesResult(RenderCapabilities(capabilities, overview.Elevated), overview.Elevated, capabilities);
    }

    internal static string RenderOverview(SystemOverview overview)
    {
        var builder = new StringBuilder();

        builder.Append(overview.MachineName).Append(" - ").Append(overview.OperatingSystem)
            .Append(" (").Append(overview.Architecture).AppendLine(")");

        builder.Append("Running as ").Append(overview.UserName)
            .Append(overview.Elevated ? " (elevated)" : " (NOT elevated)").AppendLine();

        if (overview.Is64BitOperatingSystem && !overview.Is64BitProcess)
        {
            // A misdeployment, not a curiosity: the 32-bit build cannot dump a 64-bit process at all,
            // and it cannot drive Procmon here either, since the 32-bit Procmon refuses to capture on
            // x64. Both failures appear later and look like tool bugs rather than a wrong download.
            builder.AppendLine(
                "WARNING: this is the 32-bit build of the server running on 64-bit Windows. Use the " +
                "win-x64 build here - the 32-bit one cannot dump 64-bit processes and cannot capture " +
                "activity on this OS.");
        }

        builder.Append("Up ").Append(FormatUptime(overview.Uptime))
            .Append(", booted ").Append(overview.BootTime.ToString("u", CultureInfo.InvariantCulture))
            .AppendLine();

        builder.Append(overview.ProcessorCount).Append(" logical processors, ")
            .Append(FormatBytes(overview.AvailablePhysicalMemoryBytes)).Append(" free of ")
            .Append(FormatBytes(overview.TotalPhysicalMemoryBytes)).AppendLine(" RAM");

        foreach (var disk in overview.Disks)
        {
            builder.Append("- ").Append(disk.Name);
            if (disk.Label is { } label)
            {
                builder.Append(" \"").Append(label).Append('"');
            }

            builder.Append(' ').Append(disk.FileSystem).Append(": ")
                .Append(FormatBytes(disk.FreeBytes)).Append(" free of ")
                .Append(FormatBytes(disk.TotalBytes));

            if (disk.PercentFree is { } percent)
            {
                builder.Append(" (").Append(percent.ToString("0.#", CultureInfo.InvariantCulture)).Append("%)");

                // Worth calling out unprompted: a nearly full volume explains a large class of
                // "it suddenly stopped working" reports on its own. Read-only media is excluded --
                // a mounted ISO is always 0% free, and flagging it teaches the reader to ignore this.
                if (percent < 5 && disk.CanRunOutOfSpace)
                {
                    builder.Append(" - CRITICALLY LOW");
                }
            }

            builder.AppendLine();
        }

        return builder.ToString().TrimEnd();
    }

    internal static string RenderCapabilities(IReadOnlyList<ToolCapability> capabilities, bool elevated)
    {
        var builder = new StringBuilder();

        var unavailable = capabilities.Count(c => c.Status == CapabilityStatus.Unavailable);
        var degraded = capabilities.Count(c => c.Status == CapabilityStatus.Degraded);

        builder.Append(capabilities.Count).Append(" tools; ")
            .Append(capabilities.Count - unavailable - degraded).Append(" fully available");

        if (degraded > 0)
        {
            builder.Append(", ").Append(degraded).Append(" degraded");
        }

        if (unavailable > 0)
        {
            builder.Append(", ").Append(unavailable).Append(" unavailable");
        }

        builder.Append(". Server is ").Append(elevated ? "elevated." : "NOT elevated.").AppendLine();

        foreach (var capability in capabilities)
        {
            builder.Append("- ").Append(capability.Tool).Append(" [").Append(capability.Status).Append("] ")
                .Append(capability.Backing);

            if (capability.Status != CapabilityStatus.Available)
            {
                builder.Append(" - ").Append(capability.Detail);
            }

            builder.AppendLine();
        }

        return builder.ToString().TrimEnd();
    }

    private static string FormatUptime(TimeSpan uptime) =>
        uptime.TotalDays >= 1
            ? $"{(int)uptime.TotalDays}d {uptime.Hours}h {uptime.Minutes}m"
            : $"{(int)uptime.TotalHours}h {uptime.Minutes}m";

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB", "PB"];
        double value = bytes;
        var unit = 0;

        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value.ToString(unit == 0 ? "0" : "0.#", CultureInfo.InvariantCulture)} {units[unit]}";
    }
}
