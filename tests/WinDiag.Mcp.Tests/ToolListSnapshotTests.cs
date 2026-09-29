using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol;
using ModelContextProtocol.Server;
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
        var actual = Snapshot();
        var golden = Path.Combine(RepositoryRoot(), "tests", "WinDiag.Mcp.Tests", "Fixtures", "tools-list.golden.json");

        if (Environment.GetEnvironmentVariable("WINDIAG_UPDATE_TOOL_SNAPSHOT") == "1")
        {
            Directory.CreateDirectory(Path.GetDirectoryName(golden)!);
            File.WriteAllText(golden, actual);
        }

        Assert.True(File.Exists(golden), $"No snapshot at {golden}. Run once with WINDIAG_UPDATE_TOOL_SNAPSHOT=1.");
        Assert.Equal(File.ReadAllText(golden).ReplaceLineEndings("\n"), actual.ReplaceLineEndings("\n"));
    }

    private static string Snapshot()
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.ClearProviders());
        ServerBuilder.ConfigureServices(services, WinDiagOptions.FromEnvironment(new System.Collections.Hashtable
        {
            ["WINDIAG_ALLOW_SELF_UPDATE"] = "1",
            ["WINDIAG_ALLOW_COMMAND_EXECUTION"] = "1"
        }));

        using var provider = services.BuildServiceProvider();
        var tools = provider.GetServices<McpServerTool>()
            .Select(tool => tool.ProtocolTool)
            .OrderBy(tool => tool.Name, StringComparer.Ordinal)
            .ToList();

        var options = new JsonSerializerOptions(McpJsonUtilities.DefaultOptions) { WriteIndented = true };
        return JsonSerializer.Serialize(tools, options) + "\n";
    }

    private static string RepositoryRoot()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            if (File.Exists(Path.Combine(d.FullName, "WinDiag.Mcp.sln")))
            {
                return d.FullName;
            }
        }

        throw new InvalidOperationException($"No WinDiag.Mcp.sln above {AppContext.BaseDirectory}.");
    }
}
