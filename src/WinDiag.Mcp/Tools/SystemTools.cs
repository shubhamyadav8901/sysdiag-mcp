using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics.SystemInfo;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>system_overview</c>.</summary>
public sealed record SystemOverviewResult(string Summary, SystemOverview System);

/// <summary>Orientation: what is this machine. What can be seen on it is <c>capabilities</c>, in the kit.</summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class SystemTools
{
    private readonly ISystemInspector _system;

    public SystemTools(ISystemInspector system)
    {
        _system = system;
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

        builder.Append("Up ").Append(TextFormat.Uptime(overview.Uptime))
            .Append(", booted ").Append(overview.BootTime.ToString("u", CultureInfo.InvariantCulture))
            .AppendLine();

        builder.Append(overview.ProcessorCount).Append(" logical processors, ")
            .Append(TextFormat.Bytes(overview.AvailablePhysicalMemoryBytes)).Append(" free of ")
            .Append(TextFormat.Bytes(overview.TotalPhysicalMemoryBytes)).AppendLine(" RAM");

        foreach (var disk in overview.Disks)
        {
            builder.Append("- ").Append(disk.Name);
            if (disk.Label is { } label)
            {
                builder.Append(" \"").Append(label).Append('"');
            }

            builder.Append(' ').Append(disk.FileSystem).Append(": ")
                .Append(TextFormat.Bytes(disk.FreeBytes)).Append(" free of ")
                .Append(TextFormat.Bytes(disk.TotalBytes));

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
}
