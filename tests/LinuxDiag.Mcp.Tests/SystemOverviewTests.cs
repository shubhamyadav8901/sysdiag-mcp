using LinuxDiag.Mcp.Diagnostics;
using LinuxDiag.Mcp.Diagnostics.SystemInfo;
using LinuxDiag.Mcp.Tools;

namespace LinuxDiag.Mcp.Tests;

public sealed class SystemOverviewTests
{
    private static SystemOverview Overview(params MountedFilesystem[] filesystems) => new(
        "host", "root", "Ubuntu 24.04 LTS", "Linux 6.6", "X64", true,
        DateTimeOffset.UnixEpoch, TimeSpan.FromHours(3), 8, 16L << 30, 8L << 30, filesystems);

    [Fact]
    public void A_nearly_full_writable_filesystem_is_called_out_and_a_read_only_one_is_not()
    {
        var summary = SystemTools.RenderOverview(Overview(
            new("/", "/dev/sda1", "ext4", 100L << 30, 1L << 30, ReadOnly: false),
            new("/media/iso", "/dev/sr0", "iso9660", 5L << 30, 0, ReadOnly: true)));

        Assert.Contains("- / (/dev/sda1 ext4)", summary, StringComparison.Ordinal);
        Assert.Single(summary.Split('\n'), line => line.Contains("CRITICALLY LOW", StringComparison.Ordinal));
        Assert.Contains("(root)", summary, StringComparison.Ordinal);
    }

    [Fact]
    public void A_mount_that_did_not_answer_is_shown_not_hidden()
    {
        var summary = SystemTools.RenderOverview(Overview(new MountedFilesystem("/mnt/nfs", "srv:/x", "nfs4", 0, 0, false)));

        Assert.Contains("/mnt/nfs", summary, StringComparison.Ordinal);
        Assert.Contains("size unknown", summary, StringComparison.Ordinal);
    }

    [LinuxFact]
    public void The_live_overview_describes_this_machine()
    {
        var overview = new LinuxSystemInspector(new LinuxPrivilegeProbe()).Describe();

        Assert.False(string.IsNullOrWhiteSpace(overview.OperatingSystem));
        Assert.True(overview.TotalPhysicalMemoryBytes > 0);
        Assert.True(overview.Uptime > TimeSpan.Zero);
        Assert.Contains(overview.Filesystems, fs => fs.MountPoint == "/" && fs.TotalBytes > 0);
    }
}
