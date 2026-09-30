using System.Diagnostics;
using LinuxDiag.Mcp.Linux.Native;
using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Tests;

public sealed class LockParserTests : IDisposable
{
    private readonly string _root = Directory.CreateDirectory(
        Path.Combine(Path.GetTempPath(), $"ld-lock-{Guid.NewGuid():N}")).FullName;

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    [Fact]
    public void A_proc_locks_line_gives_kind_access_pid_and_the_hex_device_with_a_decimal_inode()
    {
        // Captured from WSL Ubuntu.
        var entry = ProcLocks.ParseLine("1: FLOCK  ADVISORY  WRITE 206 08:30:44684 0 EOF");

        Assert.Equal(new LockEntry(1, false, "FLOCK", "ADVISORY", "WRITE", 206, 0x08, 0x30, 44684), entry);
    }

    [Fact]
    public void A_waiter_an_ofd_lock_and_a_lease_parse_too()
    {
        var entries = ProcLocks.Parse(
            "1: POSIX  ADVISORY  WRITE 300 fd:01:9 0 EOF\n" +
            "1: -> POSIX  ADVISORY  WRITE 301 fd:01:9 0 EOF\n" +
            "2: OFDLCK ADVISORY  READ  -1 00:3d:642 0 EOF\n" +
            "3: LEASE  ACTIVE    READ 400 08:30:1 0 EOF\n");

        Assert.True(entries[1].Waiting);
        Assert.Equal(301, entries[1].ProcessId);
        Assert.Equal(0xfdU, entries[0].DeviceMajor);
        Assert.Equal(-1, entries[2].ProcessId);
        Assert.Equal("LEASE", entries[3].Type);
    }

    [Fact]
    public void A_short_line_is_a_format_error()
    {
        Assert.Throws<FormatException>(() => ProcLocks.ParseLine("1: FLOCK ADVISORY"));
    }

    [Fact]
    public void Every_captured_distro_parses()
    {
        foreach (var distro in ProcParserTests.Distros())
        {
            Assert.NotEmpty(ProcLocks.Parse(ProcParserTests.Fixture(distro, "locks")!));
            var locked = FdInfo.Parse(ProcParserTests.Fixture(distro, "pid-fdinfo-locked")!);
            var held = ProcLocks.ParseLine(Assert.Single(locked.Locks));
            Assert.Equal("FLOCK", held.Type);

            // The capture holds the lock in a live process, so /proc/locks shows the same lock: same creator,
            // device and inode -- the key who_locks_path confirms a /proc/locks entry by.
            Assert.Contains(ProcLocks.Parse(ProcParserTests.Fixture(distro, "locks")!),
                e => e.ProcessId == held.ProcessId && e.Inode == held.Inode &&
                     e.DeviceMajor == held.DeviceMajor && e.DeviceMinor == held.DeviceMinor);
        }
    }

    [LinuxFact]
    public void Identify_sees_a_hard_link_as_the_same_file_a_fifo_as_a_fifo_and_nothing_as_null()
    {
        var file = Path.Combine(_root, "a");
        var link = Path.Combine(_root, "b");
        var fifo = Path.Combine(_root, "f");
        File.WriteAllText(file, "x");
        Run("ln", file, link);
        Run("mkfifo", fifo);

        Assert.Equal(LibC.Identify(file), LibC.Identify(link));
        Assert.True(LibC.Identify(fifo)!.Value.IsFifo);
        Assert.False(LibC.Identify(file)!.Value.IsFifo);
        Assert.Null(LibC.Identify(Path.Combine(_root, "missing")));
    }

    internal static void Run(string program, params string[] arguments)
    {
        using var process = Process.Start(new ProcessStartInfo(program, arguments) { RedirectStandardError = true })!;
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, $"{program} failed: {process.StandardError.ReadToEnd()}");
    }
}
