using WinDiag.Mcp.Diagnostics.Services;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

public sealed class ServiceRenderingTests
{
    private static ServiceInfo Service(
        string status = "Running",
        string startType = "Automatic",
        bool delayed = false) =>
        new(
            ServiceName: "Spooler",
            DisplayName: "Print Spooler",
            Description: "Loads files to memory for later printing.",
            Status: status,
            StartType: startType,
            DelayedAutoStart: delayed,
            ServiceType: "Win32OwnProcess",
            ImagePath: @"%SystemRoot%\System32\spoolsv.exe",
            Account: "LocalSystem",
            DependsOn: ["RPCSS", "http"],
            DependedOnBy: ["Fax"]);

    [Fact]
    public void Reports_configuration_and_live_state_together()
    {
        var summary = ServiceTools.Render(new ServiceQueryResult("Spooler", Service(), []));

        Assert.Contains("Spooler (Print Spooler)", summary);
        Assert.Contains("Running", summary);
        Assert.Contains("start type Automatic", summary);
        Assert.Contains("LocalSystem", summary);
        Assert.Contains(@"%SystemRoot%\System32\spoolsv.exe", summary);
        Assert.Contains("RPCSS, http", summary);
        Assert.Contains("Fax", summary);
    }

    [Fact]
    public void Calls_out_a_service_configured_to_autostart_that_is_not_running()
    {
        // The contradiction between configured and actual is the whole point of the tool; leaving the
        // reader to spot it across two fields wastes the observation.
        var summary = ServiceTools.Render(
            new ServiceQueryResult("Spooler", Service(status: "Stopped"), []));

        Assert.Contains("configured to start automatically but is currently stopped", summary);
        Assert.Contains("System event log", summary);
    }

    [Fact]
    public void Calls_out_a_disabled_service()
    {
        var summary = ServiceTools.Render(
            new ServiceQueryResult("Spooler", Service(status: "Stopped", startType: "Disabled"), []));

        Assert.Contains("DISABLED", summary);
        Assert.DoesNotContain("configured to start automatically", summary);
    }

    [Fact]
    public void Marks_a_delayed_autostart_service()
    {
        var summary = ServiceTools.Render(
            new ServiceQueryResult("Spooler", Service(delayed: true), []));

        Assert.Contains("(delayed)", summary);
    }

    [Fact]
    public void Suggests_near_matches_when_the_name_is_wrong()
    {
        // A typo'd service name is the most common cause of an empty answer, and guessing again blindly
        // wastes a round trip.
        var summary = ServiceTools.Render(
            new ServiceQueryResult("spool", null, ["Spooler (Print Spooler)"]));

        Assert.Contains("No service named 'spool' exists", summary);
        Assert.Contains("Did you mean", summary);
        Assert.Contains("Spooler (Print Spooler)", summary);
    }

    [Fact]
    public void Says_so_plainly_when_there_are_no_near_matches_either()
    {
        var summary = ServiceTools.Render(new ServiceQueryResult("nonesuch", null, []));

        Assert.Contains("No service named 'nonesuch' exists", summary);
        Assert.DoesNotContain("Did you mean", summary);
    }

    [Fact]
    public void Renders_absent_optional_fields_without_claiming_a_value()
    {
        var bare = new ServiceInfo(
            "Odd", null, null, "Stopped", "(unknown)", false, "(unknown)", null, null, [], []);

        var summary = ServiceTools.Render(new ServiceQueryResult("Odd", bare, []));

        Assert.Contains("Runs as: (not recorded)", summary);
        Assert.Contains("Image: (not recorded)", summary);
        Assert.Contains("Depends on: (none)", summary);
    }
}
