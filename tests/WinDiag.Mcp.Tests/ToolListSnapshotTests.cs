using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WinDiag.Mcp;
using WinDiag.Mcp.Configuration;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// Pins the whole tool surface -- every name, description and schema -- so a refactor that moves code
/// between assemblies cannot change what a caller sees without a test saying so.
/// </summary>
/// <remarks>
/// Sorted by name because registration order is an implementation detail that the move changes on
/// purpose; the order a client receives tools in is not a contract, their content is. Regenerate
/// deliberately with WINDIAG_UPDATE_TOOL_SNAPSHOT=1 and review the diff: the only change the server-kit
/// extraction was allowed to make was in the put_file/get_file descriptions.
/// </remarks>
public sealed class ToolListSnapshotTests
{
    [Fact]
    public void The_tool_surface_matches_the_recorded_snapshot()
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.ClearProviders());
        ServerBuilder.ConfigureServices(services, WinDiagOptions.FromEnvironment(new System.Collections.Hashtable
        {
            ["WINDIAG_ALLOW_SELF_UPDATE"] = "1",
            ["WINDIAG_ALLOW_COMMAND_EXECUTION"] = "1"
        }));
        using var provider = services.BuildServiceProvider();

        Diag.Mcp.Server.Tests.ToolSnapshotGuard.AssertMatchesGolden(
            provider,
            Diag.Mcp.Server.Tests.ToolSnapshotGuard.RepositoryFile("tests", "WinDiag.Mcp.Tests", "Fixtures", "tools-list.golden.json"),
            "WINDIAG_UPDATE_TOOL_SNAPSHOT");
    }
}
