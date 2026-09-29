using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Tests;

public sealed class ParserTests
{
    private static string Fixture(string distro, string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", distro, name));

    [Theory]
    [InlineData("ubuntu", "Ubuntu")]
    [InlineData("debian", "Debian")]
    public void Every_captured_distro_parses(string distro, string name)
    {
        Assert.Contains(name, OsRelease.PrettyName(Fixture(distro, "os-release")), StringComparison.Ordinal);

        var (total, available) = Meminfo.Parse(Fixture(distro, "meminfo"));
        Assert.True(total > 0 && available > 0 && available <= total, $"total={total} available={available}");

        Assert.True(Uptime.Parse(Fixture(distro, "uptime")) > TimeSpan.Zero);

        var mounts = Mounts.Parse(Fixture(distro, "mounts"));
        Assert.Contains(mounts, m => m.MountPoint == "/" && Mounts.IsDiskLike(m));
        Assert.DoesNotContain(mounts, m => m.FileSystem == "proc" && Mounts.IsDiskLike(m));
    }

    [Fact]
    public void Os_release_is_unquoted_and_falls_back_when_pretty_name_is_missing()
    {
        Assert.Equal("Debian GNU/Linux 12 (bookworm)",
            OsRelease.PrettyName("NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"));
        Assert.Equal("Alpine 3.19", OsRelease.PrettyName("NAME=Alpine\nVERSION_ID=3.19\n"));
        Assert.Equal("Linux", OsRelease.PrettyName(""));
    }

    [Fact]
    public void Meminfo_is_read_in_bytes()
    {
        var (total, available) = Meminfo.Parse("MemTotal:        8000 kB\nMemFree:  100 kB\nMemAvailable:    6000 kB\n");

        Assert.Equal(8000L * 1024, total);
        Assert.Equal(6000L * 1024, available);
    }

    [Fact]
    public void Meminfo_without_mem_available_estimates_it_rather_than_reporting_zero()
    {
        // Review Focus 4: older kernels and some containers have no MemAvailable, and zero would read as
        // memory exhausted. Free plus reclaimable page cache is the estimate the kernel itself used.
        var (_, available) = Meminfo.Parse("MemTotal: 8000 kB\nMemFree: 1000 kB\nBuffers: 500 kB\nCached: 2500 kB\n");

        Assert.Equal(4000L * 1024, available);
    }

    [Fact]
    public void Uptime_is_the_first_field_in_seconds()
    {
        Assert.Equal(TimeSpan.FromSeconds(12345.67), Uptime.Parse("12345.67 54321.00\n"));
    }

    [Fact]
    public void A_mount_point_with_a_space_is_unescaped()
    {
        // Review Focus 3: the kernel writes a space in a mount point as \040. Shown escaped, the disk
        // list names a directory that does not exist.
        var mounts = Mounts.Parse("/dev/sdb1 /mnt/my\\040disk ext4 rw,relatime 0 0\n");

        Assert.Equal("/mnt/my disk", Assert.Single(mounts).MountPoint);

        // Both edges of the escape: one ending the field, and one cut short, which is kept as written.
        Assert.Equal("/mnt/end ", Assert.Single(Mounts.Parse("/dev/sdb1 /mnt/end\\040 ext4 rw 0 0\n")).MountPoint);
        Assert.Equal("/mnt/x\\04", Assert.Single(Mounts.Parse("/dev/sdb1 /mnt/x\\04 ext4 rw 0 0\n")).MountPoint);
    }

    [Fact]
    public void The_wsl_windows_drive_device_is_unescaped_too()
    {
        // Captured from WSL: drvfs names its device C:\ and the kernel escapes the backslash as \134.
        var drive = Mounts.Parse(Fixture("ubuntu", "mounts")).Single(m => m.MountPoint == "/mnt/c");

        Assert.Equal("C:\\", drive.Device);
        Assert.True(Mounts.IsDiskLike(drive));
    }

    [Fact]
    public void Pseudo_filesystems_and_snap_images_are_not_disks()
    {
        var mounts = Mounts.Parse(
            "proc /proc proc rw 0 0\n" +
            "tmpfs /run tmpfs rw 0 0\n" +
            "/dev/loop3 /snap/core/1 squashfs ro 0 0\n" +
            "overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0\n" +
            "/dev/sda1 / ext4 rw 0 0\n" +
            "server:/export /mnt/nfs nfs4 rw 0 0\n");

        Assert.Equal(["/", "/mnt/nfs"], mounts.Where(Mounts.IsDiskLike).Select(m => m.MountPoint));
        Assert.True(mounts.Single(m => m.MountPoint == "/snap/core/1").ReadOnly);
    }
}
