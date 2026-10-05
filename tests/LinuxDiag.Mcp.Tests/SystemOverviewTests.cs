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

    [Fact]
    public void Each_mount_is_probed_on_a_thread_of_its_own_so_a_starved_pool_cannot_make_a_healthy_mount_time_out()
    {
        var mounts = new[] { new LinuxDiag.Mcp.Linux.Parsers.MountEntry("/dev/sda1", "/", "ext4", false) };
        bool? onPool = null;

        LinuxSystemInspector.Filesystems(
            mounts, _ => { onPool = Thread.CurrentThread.IsThreadPoolThread; return (100, 40); }, TimeSpan.FromSeconds(5));

        Assert.False(onPool);
    }

    [Fact]
    public void A_mount_whose_size_never_comes_back_is_reported_unknown_instead_of_hanging_the_call()
    {
        // statvfs on a hard NFS mount whose server has gone blocks rather than failing. Waited on
        // inline, system_overview would never return -- and update_self waits for in-flight calls.
        using var never = new ManualResetEventSlim(false);
        var mounts = new[]
        {
            new LinuxDiag.Mcp.Linux.Parsers.MountEntry("srv:/x", "/mnt/hung", "nfs4", false),
            new LinuxDiag.Mcp.Linux.Parsers.MountEntry("/dev/sda1", "/", "ext4", false),
        };
        try
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();
            var filesystems = LinuxSystemInspector.Filesystems(
                mounts,
                mountPoint => { if (mountPoint == "/mnt/hung") { never.Wait(); } return (100, 40); },
                TimeSpan.FromMilliseconds(200));

            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"took {watch.Elapsed}");
            Assert.Equal(0, filesystems.Single(f => f.MountPoint == "/mnt/hung").TotalBytes);
            Assert.Equal(100, filesystems.Single(f => f.MountPoint == "/").TotalBytes);
        }
        finally
        {
            never.Set();
        }
    }

    [Fact]
    public void Of_two_mounts_stacked_on_one_path_the_visible_later_one_is_reported()
    {
        // /proc/self/mounts lists mounts in the order they were made; a later mount on the same path hides
        // the earlier one, so the last entry is what a process actually sees there.
        var filesystems = LinuxSystemInspector.Filesystems(
            [
                new LinuxDiag.Mcp.Linux.Parsers.MountEntry("/dev/sda2", "/data", "ext4", false),
                new LinuxDiag.Mcp.Linux.Parsers.MountEntry("/dev/sdb1", "/data", "xfs", false),
            ],
            _ => (100, 50),
            TimeSpan.FromSeconds(1));

        Assert.Equal("/dev/sdb1", Assert.Single(filesystems).Device);
    }

    [LinuxFact]
    public void The_live_overview_describes_this_machine()
    {
        var overview = new LinuxSystemInspector(new LinuxPrivilegeProbe()).Describe();

        Assert.False(string.IsNullOrWhiteSpace(overview.OperatingSystem));
        Assert.True(overview.TotalPhysicalMemoryBytes > 0);
        Assert.True(overview.Uptime > TimeSpan.Zero);
        Assert.Contains(overview.Filesystems, fs => fs.MountPoint == "/" && fs.TotalBytes > 0);

        // The kernel release, not the distribution again: RuntimeInformation.OSDescription returns the
        // distro's name on Linux, which is how the first live run printed "Ubuntu 24.04.4 LTS" twice.
        Assert.StartsWith("Linux ", overview.Kernel, StringComparison.Ordinal);
        Assert.Matches(@"^Linux \d+\.\d+", overview.Kernel);
        Assert.NotEqual(overview.OperatingSystem, overview.Kernel);
    }
}
