using Diag.Mcp.Server.Capabilities;

namespace Diag.Mcp.Server.Tests;

/// <summary>The rules that turn a server's requirement table into a status per tool.</summary>
public sealed class CapabilityEngineTests
{
    private sealed class Table(Dictionary<string, CapabilityRequirement> requirements) : ICapabilityRequirements
    {
        public IReadOnlyDictionary<string, CapabilityRequirement> Requirements => requirements;
    }

    private sealed class Resolver(string? path) : IExecutableResolver
    {
        public ExecutableResolution Resolve(string baseName) =>
            path is null ? new(null, $"{baseName} is not installed on this machine.") : new(path, null);
    }

    private sealed class Probe(bool elevated) : IPrivilegeProbe
    {
        public bool IsElevated => elevated;
    }

    private static Dictionary<string, ToolCapability> Evaluate(bool elevated, string? resolvedPath) =>
        new CapabilityReporter(
                new Table(new()
                {
                    ["d_partial"] = new("backing D", null, "sees only this user's processes"),
                    ["a_plain"] = new("backing A", null, null),
                    ["c_needs_admin"] = new("backing C", null, null, RequiresElevation: true),
                    ["b_needs_tool"] = new("backing B", "tool", null),
                }),
                new Resolver(resolvedPath),
                new Probe(elevated))
            .Describe()
            .ToDictionary(c => c.Tool);

    [Fact]
    public void Each_rule_decides_the_status_and_the_default_wording_is_the_windows_wording()
    {
        var byTool = Evaluate(elevated: false, resolvedPath: null);

        Assert.Equal(["a_plain", "b_needs_tool", "c_needs_admin", "d_partial"], byTool.Keys);
        Assert.Equal(CapabilityStatus.Available, byTool["a_plain"].Status);
        Assert.Equal(CapabilityStatus.Unavailable, byTool["b_needs_tool"].Status);
        Assert.Equal("tool is not installed on this machine.", byTool["b_needs_tool"].Detail);
        Assert.Equal(CapabilityStatus.Unavailable, byTool["c_needs_admin"].Status);
        Assert.Equal(
            "Requires administrator rights and cannot run without them. Restart the server from an elevated terminal.",
            byTool["c_needs_admin"].Detail);
        Assert.Equal(CapabilityStatus.Degraded, byTool["d_partial"].Status);
        Assert.Equal(
            "Not elevated, so this tool sees only this user's processes. Restart the server from an elevated terminal.",
            byTool["d_partial"].Detail);
    }

    [Fact]
    public void An_elevated_server_with_the_executable_present_names_the_one_it_will_run()
    {
        var byTool = Evaluate(elevated: true, resolvedPath: "/usr/bin/tool");

        Assert.All(byTool.Values, c => Assert.Equal(CapabilityStatus.Available, c.Status));
        Assert.Equal("Ready, using /usr/bin/tool.", byTool["b_needs_tool"].Detail);
        Assert.Equal("Ready.", byTool["a_plain"].Detail);
    }
}
