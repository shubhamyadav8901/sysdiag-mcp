using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.Capabilities;
using WinDiag.Mcp.Diagnostics.External;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

public sealed class CapabilityReporterTests
{
    /// <summary>A target that deploy-target.ps1 has staged completely: every build of every tool.</summary>
    private static FakeToolLocator FullyStaged() =>
        new("handle.exe", "handle64.exe", "Procmon.exe", "Procmon64.exe");

    /// <summary>The shared engine, with this server's table and its Sysinternals resolver.</summary>
    private static CapabilityReporter Reporter(IToolLocator locator, IPrivilegeProbe privileges) =>
        new(new WindowsCapabilityRequirements(), new SysinternalsExecutableResolver(locator), privileges);

    [Fact]
    public void Covers_every_registered_tool_and_invents_none()
    {
        // The requirements table is hand-maintained, so without this it would quietly fall behind as
        // tools are added -- and `capabilities` would then confidently report on a subset while the
        // caller believed it was seeing everything. Adding a tool must mean declaring what it needs.
        // Both assemblies, because put_file, get_file and capabilities are declared in the kit.
        Diag.Mcp.Server.Tests.CapabilityTableGuard.AssertTableMatchesDeclaredTools(
            new WindowsCapabilityRequirements().Requirements, typeof(FileLockTools).Assembly, typeof(DiagServerKit).Assembly);
    }

    [Fact]
    public void Reports_a_tool_as_unavailable_when_its_executable_is_missing()
    {
        var reporter = Reporter(new FakeToolLocator(), new FakePrivilegeProbe(true));

        var handleSearch = reporter.Describe().Single(c => c.Tool == "path_handle_search");

        Assert.Equal(CapabilityStatus.Unavailable, handleSearch.Status);

        // Names the build this OS actually needs. "handle.exe is not installed" on a 64-bit box would
        // send someone to stage the one build that cannot answer.
        Assert.Contains(
            Environment.Is64BitOperatingSystem ? "handle64.exe" : "handle.exe",
            handleSearch.Detail);
    }

    [Fact]
    public void Reports_which_copy_of_a_tool_it_will_actually_run()
    {
        // Two copies of a Sysinternals binary on one machine is the normal case. "Available" without a
        // path leaves the reader unable to tell which one answered.
        var reporter = Reporter(
            new FakeToolLocator("handle.exe", "handle64.exe"), new FakePrivilegeProbe(true));

        var detail = reporter.Describe().Single(c => c.Tool == "path_handle_search").Detail;

        Assert.Contains("cmd.exe", detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Reports_a_thirty_two_bit_only_install_as_unavailable_rather_than_ready()
    {
        if (!Environment.Is64BitOperatingSystem)
        {
            return; // The 32-bit build is the correct one here, so there is nothing to reject.
        }

        // Available would be the dangerous answer: the tool would run and return nothing, and nothing
        // reads as a clean result.
        var reporter = Reporter(
            new FixedArchitectureLocator(PeImageHeader.MachineI386), new FakePrivilegeProbe(true));

        var handleSearch = reporter.Describe().Single(c => c.Tool == "path_handle_search");

        Assert.Equal(CapabilityStatus.Unavailable, handleSearch.Status);
        Assert.Contains("32-bit build", handleSearch.Detail);
    }

    [Fact]
    public void Reports_a_tool_as_degraded_when_elevation_would_change_the_answer()
    {
        // Degraded, not unavailable: handle.exe runs unelevated and returns a SHORTER list rather than
        // an error, so the distinction is exactly what stops a partial result being read as complete.
        var reporter = Reporter(FullyStaged(), new FakePrivilegeProbe(false));

        var handleSearch = reporter.Describe().Single(c => c.Tool == "path_handle_search");

        Assert.Equal(CapabilityStatus.Degraded, handleSearch.Status);
        Assert.Contains("partial", handleSearch.Detail);
    }

    [Fact]
    public void Reports_native_tools_as_available_even_without_elevation()
    {
        var reporter = Reporter(new FakeToolLocator(), new FakePrivilegeProbe(false));

        Assert.Equal(CapabilityStatus.Available, reporter.Describe().Single(c => c.Tool == "who_locks_path").Status);
    }

    [Fact]
    public void Lists_tools_in_a_stable_order()
    {
        var reporter = Reporter(FullyStaged(), new FakePrivilegeProbe(true));

        var names = reporter.Describe().Select(c => c.Tool).ToArray();

        Assert.Equal(names.OrderBy(n => n, StringComparer.Ordinal), names);
    }
}
