using System.Collections;
using LinuxDiag.Mcp.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tests;

public sealed class ToolRegistrationTests
{
    internal static LinuxDiagOptions Options(bool readOnly = false, bool selfUpdate = false, bool commands = false) =>
        LinuxDiagOptions.FromEnvironment(new Hashtable
        {
            ["LINUXDIAG_READ_ONLY"] = readOnly ? "1" : "0",
            ["LINUXDIAG_ALLOW_SELF_UPDATE"] = selfUpdate ? "1" : "0",
            ["LINUXDIAG_ALLOW_COMMAND_EXECUTION"] = commands ? "1" : "0"
        });

    internal static ServiceProvider Provider(LinuxDiagOptions options)
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.ClearProviders());
        ServerBuilder.ConfigureServices(services, options);
        return services.BuildServiceProvider();
    }

    private static string[] ToolNames(LinuxDiagOptions options)
    {
        using var provider = Provider(options);
        return provider.GetServices<McpServerTool>().Select(t => t.ProtocolTool.Name)
            .OrderBy(name => name, StringComparer.Ordinal).ToArray();
    }

    [Fact]
    public void Registers_each_tool_exactly_once()
    {
        var names = ToolNames(Options(selfUpdate: true, commands: true));

        Assert.Equal(names.Distinct(StringComparer.Ordinal).Count(), names.Length);
    }

    // The_gated_tools_follow_their_grants is added in Task 6, once both gated tools exist, so that no
    // commit in between carries a knowingly red test.

    [Fact]
    public void The_tool_surface_matches_the_recorded_snapshot()
    {
        using var provider = Provider(Options(selfUpdate: true, commands: true));

        ToolSnapshotGuard.AssertMatchesGolden(
            provider,
            ToolSnapshotGuard.RepositoryFile("tests", "LinuxDiag.Mcp.Tests", "Fixtures", "tools-list.golden.json"),
            "LINUXDIAG_UPDATE_TOOL_SNAPSHOT");
    }
}
