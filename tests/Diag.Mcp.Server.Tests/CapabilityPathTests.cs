using Diag.Mcp.Server.Capabilities;

namespace Diag.Mcp.Server.Tests;

/// <summary>A tool that reads a runtime socket or state directory says so when none is there.</summary>
public sealed class CapabilityPathTests
{
    private sealed class Table(string tool, CapabilityRequirement requirement) : ICapabilityRequirements
    {
        public IReadOnlyDictionary<string, CapabilityRequirement> Requirements { get; } =
            new Dictionary<string, CapabilityRequirement> { [tool] = requirement };
    }

    private sealed class NoHelpers : IExecutableResolver
    {
        public ExecutableResolution Resolve(string baseName) => new(null, "not used");
    }

    private sealed class Root : IPrivilegeProbe
    {
        public bool IsElevated => true;
    }

    private static ToolCapability Describe(Func<string, bool> exists) =>
        Assert.Single(new CapabilityReporter(
            new Table("container_list", new("runtime APIs", null, null, AnyOfPaths: ["/run/a.sock", "/run/b"])),
            new NoHelpers(), new Root(), exists).Describe());

    [Fact]
    public void Degraded_naming_every_path_when_none_exists()
    {
        var capability = Describe(_ => false);

        Assert.Equal(CapabilityStatus.Degraded, capability.Status);
        Assert.Contains("/run/a.sock", capability.Detail, StringComparison.Ordinal);
        Assert.Contains("/run/b", capability.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Available_when_any_one_exists()
    {
        Assert.Equal(CapabilityStatus.Available, Describe(path => path == "/run/b").Status);
    }
}
