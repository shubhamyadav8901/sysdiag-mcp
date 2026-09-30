using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Tests;

public sealed class OpenFileParserTests
{
    [Theory]
    [InlineData("socket:[31888]", "Socket")]
    [InlineData("pipe:[6400]", "Pipe")]
    [InlineData("anon_inode:[eventfd]", "AnonInode")]
    [InlineData("anon_inode:inotify", "AnonInode")]
    [InlineData("/dev/pts/0", "Device")]
    [InlineData("/proc/726/fd", "File")]
    [InlineData("/var/log/app log.txt (deleted)", "File")]
    [InlineData("net:[4026531840]", "Other")]
    public void A_descriptor_is_classified_from_its_link_text(string target, string kind)
    {
        Assert.Equal(kind, DescriptorTarget.Kind(target));
    }

    [Fact]
    public void Socket_and_pipe_inodes_are_read_only_from_their_own_form()
    {
        Assert.Equal(31888, DescriptorTarget.SocketInode("socket:[31888]"));
        Assert.Null(DescriptorTarget.SocketInode("pipe:[31888]"));
        Assert.Equal(6400, DescriptorTarget.PipeInode("pipe:[6400]"));
        Assert.True(DescriptorTarget.IsDeleted("/tmp/x (deleted)"));
        Assert.False(DescriptorTarget.IsDeleted("/tmp/x"));
    }

    [Fact]
    public void Fdinfo_gives_the_access_mode_and_every_lock_line()
    {
        // Captured from WSL Ubuntu: an flock'd descriptor's fdinfo.
        var info = FdInfo.Parse(
            "pos:\t0\nflags:\t0100002\nmnt_id:\t15\nino:\t26782\nlock:\t1: FLOCK  ADVISORY  WRITE 206 08:30:44684 0 EOF\n");

        Assert.Equal("read-write", info.Access);
        Assert.Equal("1: FLOCK  ADVISORY  WRITE 206 08:30:44684 0 EOF", Assert.Single(info.Locks));
        Assert.Equal("read", FdInfo.Parse("flags:\t02100000\n").Access);
        Assert.Equal("write", FdInfo.Parse("flags:\t0100001\n").Access);
    }

    [Fact]
    public void Passwd_maps_uids_to_names_and_keeps_the_first_of_duplicates()
    {
        var users = Passwd.Parse("root:x:0:0:root:/root:/bin/bash\njdoe:x:1000:1000::/home/jdoe:/bin/bash\ntoor:x:0:0::/:/bin/sh\nbroken\n");

        Assert.Equal("root", users[0]);
        Assert.Equal("jdoe", users[1000]);
        Assert.Equal(2, users.Count);
    }

    [Fact]
    public void Maps_group_by_file_with_spaces_and_deleted_kept_and_anonymous_memory_dropped()
    {
        // The first two lines are captured from WSL Ubuntu (`cat /proc/self/maps`); the rest pin spaces,
        // ' (deleted)' and the file-like names that are really anonymous memory.
        var files = ProcMaps.Files(ProcMaps.Parse(
            "5c494340c000-5c494340e000 r--p 00000000 08:30 37695                      /usr/bin/cat\n" +
            "5c494340e000-5c4943413000 r-xp 00002000 08:30 37695                      /usr/bin/cat\n" +
            "7f0000000000-7f0000001000 r-xp 00000000 08:30 1234                       /opt/my app/lib x.so\n" +
            "7f0000002000-7f0000003000 r-xp 00000000 08:30 99                         /usr/lib/libssl.so.3 (deleted)\n" +
            "7f0000004000-7f0000005000 rw-s 00000000 00:01 5                          /memfd:jit (deleted)\n" +
            "7f0000006000-7f0000007000 rw-s 00000000 00:01 6                          /SYSV00000000 (deleted)\n" +
            "7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0                          [stack]\n" +
            "7ffd00030000-7ffd00031000 rw-p 00000000 00:00 0\n"));

        Assert.Equal(["/usr/bin/cat", "/opt/my app/lib x.so", "/usr/lib/libssl.so.3"], files.Select(f => f.Path));
        var cat = files[0];
        Assert.Equal(0x5c494340c000UL, cat.BaseAddress);
        Assert.Equal(0x7000, cat.SizeBytes);
        Assert.True(cat.Executable);
        Assert.True(files[2].Deleted);
        Assert.False(files[1].Deleted);

        var first = ProcMaps.Parse("5c494340c000-5c494340e000 r--p 00000000 08:30 37695   /usr/bin/cat\n")[0];
        Assert.Equal((0x08U, 0x30U, 37695L), (first.DeviceMajor, first.DeviceMinor, first.Inode));
    }

    [Fact]
    public void Every_captured_distro_parses()
    {
        foreach (var distro in ProcParserTests.Distros())
        {
            Assert.Contains(ProcMaps.Files(ProcMaps.Parse(ProcParserTests.Fixture(distro, "pid-maps")!)),
                f => f.Path.EndsWith("/cat", StringComparison.Ordinal));
            Assert.Single(FdInfo.Parse(ProcParserTests.Fixture(distro, "pid-fdinfo-locked")!).Locks);
        }
    }
}
