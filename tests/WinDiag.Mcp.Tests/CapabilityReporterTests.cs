using System.Reflection;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics.Capabilities;
using WinDiag.Mcp.Diagnostics.External;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

public sealed class CapabilityReporterTests
{
    /// <summary>Every tool name the assembly actually registers with the MCP SDK.</summary>
    private static IEnumerable<string> RegisteredToolNames() =>
        typeof(FileLockTools).Assembly.GetTypes()
            .Where(type => type.GetCustomAttribute<McpServerToolTypeAttribute>() is not null)
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            .Select(method => method.GetCustomAttribute<McpServerToolAttribute>())
            .Where(attribute => attribute?.Name is not null)
            .Select(attribute => attribute!.Name!);

    [Fact]
    public void Covers_every_registered_tool_and_invents_none()
    {
        // The requirements table is hand-maintained, so without this it would quietly fall behind as
        // tools are added -- and `capabilities` would then confidently report on a subset while the
        // caller believed it was seeing everything. Adding a tool must mean declaring what it needs.
        var registered = RegisteredToolNames().OrderBy(name => name, StringComparer.Ordinal).ToArray();
        var declared = CapabilityReporter.Requirements.Keys.OrderBy(name => name, StringComparer.Ordinal).ToArray();

        Assert.Equal(registered, declared);
    }

    [Fact]
    public void Reports_a_tool_as_unavailable_when_its_executable_is_missing()
    {
        var reporter = new CapabilityReporter(new StubToolLocator(resolves: false), new FakePrivilegeProbe(true));

        var handleSearch = reporter.Describe().Single(c => c.Tool == "path_handle_search");

        Assert.Equal(CapabilityStatus.Unavailable, handleSearch.Status);
        Assert.Contains("handle.exe", handleSearch.Detail);
    }

    [Fact]
    public void Reports_a_tool_as_degraded_when_elevation_would_change_the_answer()
    {
        // Degraded, not unavailable: handle.exe runs unelevated and returns a SHORTER list rather than
        // an error, so the distinction is exactly what stops a partial result being read as complete.
        var reporter = new CapabilityReporter(new StubToolLocator(resolves: true), new FakePrivilegeProbe(false));

        var handleSearch = reporter.Describe().Single(c => c.Tool == "path_handle_search");

        Assert.Equal(CapabilityStatus.Degraded, handleSearch.Status);
        Assert.Contains("partial", handleSearch.Detail);
    }

    [Fact]
    public void Reports_native_tools_as_available_even_without_elevation()
    {
        var reporter = new CapabilityReporter(new StubToolLocator(resolves: false), new FakePrivilegeProbe(false));

        Assert.Equal(CapabilityStatus.Available, reporter.Describe().Single(c => c.Tool == "who_locks_path").Status);
    }

    [Fact]
    public void Lists_tools_in_a_stable_order()
    {
        var reporter = new CapabilityReporter(new StubToolLocator(resolves: true), new FakePrivilegeProbe(true));

        var names = reporter.Describe().Select(c => c.Tool).ToArray();

        Assert.Equal(names.OrderBy(n => n, StringComparer.Ordinal), names);
    }

    private sealed class StubToolLocator(bool resolves) : IToolLocator
    {
        public string Resolve(string executableName) =>
            resolves ? @"C:\tools\" + executableName : throw new ToolNotFoundException(executableName);

        public bool TryResolve(string executableName, out string fullPath)
        {
            fullPath = resolves ? @"C:\tools\" + executableName : string.Empty;
            return resolves;
        }
    }
}
