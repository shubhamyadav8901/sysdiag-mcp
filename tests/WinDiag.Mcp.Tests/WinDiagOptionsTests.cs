using System.Collections;
using WinDiag.Mcp.Configuration;

namespace WinDiag.Mcp.Tests;

public sealed class WinDiagOptionsTests
{
    private static Hashtable Env(params (string Key, string Value)[] entries)
    {
        var table = new Hashtable();
        foreach (var (key, value) in entries)
        {
            table[key] = value;
        }

        return table;
    }

    [Fact]
    public void Uses_documented_defaults_when_nothing_is_set()
    {
        var options = WinDiagOptions.FromEnvironment(Env());

        Assert.False(options.ReadOnly);
        Assert.Equal(TimeSpan.FromSeconds(120), options.ExternalToolTimeout);
        Assert.Equal(50_000, options.MaxResults);

        // 30 minutes clears capture_activity's ~21-minute worst case, which is the call most likely to
        // be running when someone updates and the one whose truncation prompted the drain.
        Assert.Equal(TimeSpan.FromSeconds(1800), options.UpdateDrainTimeout);
    }

    [Fact]
    public void Rejects_an_update_drain_outside_the_supported_range()
    {
        // Zero is refused rather than read as "do not wait": force is how you ask for that, per call,
        // and a silent fleet-wide opt-out of the drain is exactly the accident this feature removes.
        Assert.Throws<ConfigurationException>(
            () => WinDiagOptions.FromEnvironment(Env(("WINDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS", "0"))));

        // The ceiling is a day, not the hour used for a single external tool, so covering a
        // full-length run_command stays possible.
        Assert.Throws<ConfigurationException>(
            () => WinDiagOptions.FromEnvironment(Env(("WINDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS", "86401"))));

        Assert.Equal(
            TimeSpan.FromSeconds(86_400),
            WinDiagOptions.FromEnvironment(Env(("WINDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS", "86400"))).UpdateDrainTimeout);
    }

    [Theory]
    [InlineData("1")]
    [InlineData("true")]
    [InlineData("YES")]
    [InlineData("On")]
    public void Accepts_the_documented_truthy_spellings(string value)
    {
        Assert.True(WinDiagOptions.FromEnvironment(Env(("WINDIAG_READ_ONLY", value))).ReadOnly);
    }

    [Fact]
    public void Rejects_a_misspelled_boolean_rather_than_defaulting_it()
    {
        // Defaulting here would silently grant write access on a server the operator meant to lock
        // down, which is the failure mode worth being strict about.
        var ex = Assert.Throws<ConfigurationException>(
            () => WinDiagOptions.FromEnvironment(Env(("WINDIAG_READ_ONLY", "ture"))));

        Assert.Contains("WINDIAG_READ_ONLY", ex.Message);
    }

    [Fact]
    public void Rejects_a_timeout_outside_the_supported_range()
    {
        Assert.Throws<ConfigurationException>(
            () => WinDiagOptions.FromEnvironment(Env(("WINDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS", "0"))));

        Assert.Throws<ConfigurationException>(
            () => WinDiagOptions.FromEnvironment(Env(("WINDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS", "99999"))));
    }

    [Fact]
    public void Rejects_a_non_numeric_timeout()
    {
        Assert.Throws<ConfigurationException>(
            () => WinDiagOptions.FromEnvironment(Env(("WINDIAG_MAX_RESULTS", "lots"))));
    }

    [Fact]
    public void Describe_reports_every_option_for_the_startup_log()
    {
        var description = WinDiagOptions.FromEnvironment(Env(("WINDIAG_READ_ONLY", "1"))).Describe();

        Assert.Contains("readOnly=True", description);
        Assert.Contains("externalToolTimeout=120s", description);
        Assert.Contains("updateDrainTimeout=1800s", description);
        Assert.Contains("maxResults=50000", description);
    }
}
