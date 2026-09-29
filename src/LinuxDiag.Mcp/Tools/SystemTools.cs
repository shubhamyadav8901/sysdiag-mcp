using System.ComponentModel;
using System.Globalization;
using System.Text;
using LinuxDiag.Mcp.Diagnostics.SystemInfo;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

/// <summary>Structured result of <c>system_overview</c>.</summary>
public sealed record SystemOverviewResult(string Summary, SystemOverview System);

[McpServerToolType]
public sealed class SystemTools(ISystemInspector system)
{
    [McpServerTool(
        Name = "system_overview",
        Title = "System overview",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Describe the machine: distribution and kernel, architecture, uptime and boot time, processor " +
        "count, memory, mounted filesystems with free space, the account the server runs as, and whether " +
        "it is root. Good first call in any investigation - it establishes the ground truth and surfaces " +
        "environmental causes (a full disk, a very recent reboot, exhausted memory) before you go looking " +
        "for something subtler.")]
    public SystemOverviewResult SystemOverview()
    {
        var overview = system.Describe();
        return new SystemOverviewResult(RenderOverview(overview), overview);
    }

    internal static string RenderOverview(SystemOverview overview)
    {
        var builder = new StringBuilder();

        builder.Append(overview.MachineName).Append(" - ").Append(overview.OperatingSystem)
            .Append(" (").Append(overview.Architecture).Append(", ").Append(overview.Kernel).AppendLine(")");
        builder.Append("Running as ").Append(overview.UserName)
            .Append(overview.Elevated ? " (root)" : " (NOT root)").AppendLine();
        builder.Append("Up ").Append(TextFormat.Uptime(overview.Uptime))
            .Append(", booted ").Append(overview.BootTime.ToString("u", CultureInfo.InvariantCulture)).AppendLine();
        builder.Append(overview.ProcessorCount).Append(" logical processors, ")
            .Append(TextFormat.Bytes(overview.AvailablePhysicalMemoryBytes)).Append(" available of ")
            .Append(TextFormat.Bytes(overview.TotalPhysicalMemoryBytes)).AppendLine(" RAM");

        foreach (var fs in overview.Filesystems)
        {
            builder.Append("- ").Append(fs.MountPoint).Append(" (").Append(fs.Device).Append(' ')
                .Append(fs.FileSystem).Append(fs.ReadOnly ? ", read-only" : string.Empty).Append("): ");

            if (fs.TotalBytes == 0)
            {
                builder.AppendLine("size unknown - the mount did not answer");
                continue;
            }

            builder.Append(TextFormat.Bytes(fs.FreeBytes)).Append(" free of ").Append(TextFormat.Bytes(fs.TotalBytes));
            if (fs.PercentFree is { } percent)
            {
                builder.Append(" (").Append(percent.ToString("0.#", CultureInfo.InvariantCulture)).Append("%)");
                if (percent < 5 && fs.CanRunOutOfSpace)
                {
                    builder.Append(" - CRITICALLY LOW");
                }
            }

            builder.AppendLine();
        }

        return builder.ToString().TrimEnd();
    }
}
