using System.Collections;
using LinuxDiag.Mcp.Configuration;

namespace LinuxDiag.Mcp.Tests;

public sealed class OptionsTests
{
    [Fact]
    public void Defaults_mirror_windiag_except_the_artifact_directory()
    {
        var options = LinuxDiagOptions.FromEnvironment(new Hashtable());

        Assert.False(options.ReadOnly);
        Assert.False(options.AllowSelfUpdate);
        Assert.False(options.AllowCommandExecution);
        Assert.Equal(TimeSpan.FromSeconds(120), options.ExternalToolTimeout);
        Assert.Equal(TimeSpan.FromSeconds(1800), options.UpdateDrainTimeout);
        Assert.Equal(50_000, options.MaxResults);
        Assert.Null(options.HttpBind);

        // Root-owned and persistent. The temp directory would be the shared, world-writable /tmp.
        Assert.Equal("/var/lib/linuxdiag", options.ArtifactDirectory);
    }

    [Fact]
    public void Every_setting_is_read_from_its_linuxdiag_variable()
    {
        var options = LinuxDiagOptions.FromEnvironment(new Hashtable
        {
            ["LINUXDIAG_READ_ONLY"] = "1",
            ["LINUXDIAG_ALLOW_SELF_UPDATE"] = "yes",
            ["LINUXDIAG_ALLOW_COMMAND_EXECUTION"] = "true",
            ["LINUXDIAG_ALLOW_ARBITRARY_WRITE"] = "on",
            ["LINUXDIAG_ALLOW_ARBITRARY_READ"] = "1",
            ["LINUXDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS"] = "30",
            ["LINUXDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS"] = "60",
            ["LINUXDIAG_MAX_RESULTS"] = "10",
            ["LINUXDIAG_HTTP_BIND"] = "http://0.0.0.0:4024",
            ["LINUXDIAG_TOKEN"] = "t",
            ["LINUXDIAG_ARTIFACT_DIR"] = "/srv/diag",
            ["LINUXDIAG_SERVICE_NAME"] = "linuxdiag"
        });

        Assert.True(options.ReadOnly && options.AllowSelfUpdate && options.AllowCommandExecution);
        Assert.True(options.AllowArbitraryWrite && options.AllowArbitraryRead);
        Assert.Equal(TimeSpan.FromSeconds(30), options.ExternalToolTimeout);
        Assert.Equal(TimeSpan.FromSeconds(60), options.UpdateDrainTimeout);
        Assert.Equal(10, options.MaxResults);
        Assert.Equal("http://0.0.0.0:4024", options.HttpBind);
        Assert.Equal("t", options.Token);
        Assert.Equal(Path.GetFullPath("/srv/diag"), options.ArtifactDirectory);
        Assert.Equal("linuxdiag", options.ServiceName);
    }

    [Fact]
    public void A_typo_in_a_grant_fails_startup()
    {
        Assert.Throws<ConfigurationException>(() =>
            LinuxDiagOptions.FromEnvironment(new Hashtable { ["LINUXDIAG_READ_ONLY"] = "ture" }));
    }

    [Fact]
    public void The_description_never_contains_the_token()
    {
        var options = LinuxDiagOptions.FromEnvironment(new Hashtable { ["LINUXDIAG_TOKEN"] = "s3cret" });

        Assert.DoesNotContain("s3cret", options.Describe(), StringComparison.Ordinal);
        Assert.DoesNotContain("s3cret", options.ToString(), StringComparison.Ordinal);
    }
}
