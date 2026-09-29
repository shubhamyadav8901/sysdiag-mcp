using LinuxDiag.Mcp.Diagnostics;
using LinuxDiag.Mcp.Diagnostics.Capabilities;

namespace LinuxDiag.Mcp.Tests;

public sealed class CapabilityTests
{
    [Fact]
    public void A_missing_program_is_named_in_the_refusal()
    {
        var resolution = PathExecutableResolver.Find("linuxdiag-not-a-real-program", [Path.GetTempPath()]);

        Assert.Null(resolution.Path);
        Assert.Contains("linuxdiag-not-a-real-program", resolution.Problem, StringComparison.Ordinal);
    }

    [LinuxFact]
    public void A_program_on_the_standard_path_is_found()
    {
        var resolution = PathExecutableResolver.Find("sh", ["/nonexistent", "/bin", "/usr/bin"]);

        Assert.NotNull(resolution.Path);
    }

    [Fact]
    public void Refusals_are_worded_for_linux()
    {
        IPrivilegeProbe probe = new LinuxPrivilegeProbe();

        Assert.Equal("root", probe.PrivilegeName);
        Assert.Contains("as root", probe.HowToElevate, StringComparison.Ordinal);
    }
}
