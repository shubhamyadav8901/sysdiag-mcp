using System.Collections;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.SystemInfo;
using static MacDiag.Mcp.Tests.SystemOverviewTests;

namespace MacDiag.Mcp.Tests;

/// <summary>Review Focus 4 end to end: output in an unexpected shape becomes a warning, never a silent zero.</summary>
public sealed class SystemInspectorTests
{
    private sealed class Root : IPrivilegeProbe
    {
        public bool IsElevated => true;

        public string PrivilegeName => "root";

        public string HowToElevate => "n/a";
    }

    private static Task<SystemOverview> Describe(Func<string, string?> outputs) =>
        new MacSystemInspector(
            new FakeCommands((program, _) => outputs(program) is { } text ? FakeCommands.Ok(text) : new ExternalResult(1, "", "boom")),
            new Root(),
            MacDiagOptions.FromEnvironment(new Hashtable())).DescribeAsync(CancellationToken.None);

    // No mounts in these cases: sizing a volume touches the real filesystem.
    private static string? Documented(string program) => program == "mount" ? "" : Fixture(Unverified, program);

    [Fact]
    public async Task Documented_output_gives_every_value_and_no_warning()
    {
        var overview = await Describe(Documented);

        Assert.Empty(overview.Limitations);
        Assert.Equal("macOS 14.6.1 (23G93)", overview.OperatingSystem);
        Assert.Equal("Mac14,2", overview.Model);
        Assert.Equal(17179869184, overview.TotalPhysicalMemoryBytes);
        Assert.Equal((12345L + 200000 + 5000) * 16384, overview.AvailablePhysicalMemoryBytes);
    }

    [Fact]
    public async Task Vm_stat_without_its_page_size_header_is_a_warning_not_a_guess()
    {
        // Guessing 4096 would undercount an Apple Silicon Mac's memory four times over, silently.
        var overview = await Describe(p => p == "vm_stat" ? "Pages free: 10.\nPages inactive: 10.\nPages speculative: 10.\n" : Documented(p));

        Assert.Equal(0, overview.AvailablePhysicalMemoryBytes);
        Assert.Contains(overview.Limitations, l => l.Contains("page size", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_missing_vm_stat_key_is_named_rather_than_counted_as_zero()
    {
        var overview = await Describe(p => p == "vm_stat" ? "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 10.\n" : Documented(p));

        Assert.Equal(0, overview.AvailablePhysicalMemoryBytes);
        Assert.Contains(overview.Limitations, l => l.Contains("Pages inactive", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Sw_vers_that_runs_but_names_no_version_is_a_warning()
    {
        var overview = await Describe(p => p == "sw_vers" ? "ProductName: macOS\nBuildVersion: 23G93\n" : Documented(p));

        Assert.Contains(overview.Limitations, l => l.Contains("ProductVersion", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_tool_that_fails_is_a_warning_with_its_error()
    {
        var overview = await Describe(p => p == "vm_stat" ? null : Documented(p));

        Assert.Contains(overview.Limitations, l => l.Contains("vm_stat failed", StringComparison.Ordinal) && l.Contains("boom", StringComparison.Ordinal));
    }

    [Fact]
    public void Each_mount_is_probed_on_a_thread_of_its_own_so_a_starved_pool_cannot_make_a_healthy_mount_time_out()
    {
        // A probe stuck on a dead network mount keeps its thread for good; on a small, busy pool the next mount's probe
        // then waited for a thread past its whole budget, and a healthy volume read as not answering (LinuxDiag, CI).
        var mounts = new[] { new Mac.Parsers.MacMount("/dev/disk3s1", "/", "apfs", false, []) };
        bool? onPool = null;
        var limitations = new List<string>();

        var sizes = MacSystemInspector.Filesystems(
            mounts, _ => { onPool = Thread.CurrentThread.IsThreadPoolThread; return (100, 40); }, TimeSpan.FromSeconds(5), limitations);

        Assert.False(onPool);
        Assert.Equal((100L, 40L), (sizes.Single().TotalBytes, sizes.Single().FreeBytes));
        Assert.Empty(limitations);
    }

    [Fact]
    public void A_mount_whose_size_never_comes_back_is_reported_unknown_instead_of_hanging_the_call()
    {
        var mounts = new[] { new Mac.Parsers.MacMount("server:/share", "/Volumes/share", "nfs", false, []) };
        using var never = new ManualResetEventSlim();
        var limitations = new List<string>();

        try
        {
            var sizes = MacSystemInspector.Filesystems(mounts, _ => { never.Wait(); return (1, 1); }, TimeSpan.FromMilliseconds(100), limitations);

            Assert.Equal(0, sizes.Single().TotalBytes);
            Assert.Contains(limitations, l => l.Contains("/Volumes/share did not answer", StringComparison.Ordinal));
        }
        finally
        {
            never.Set();
        }
    }
}
