using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace Diag.Mcp.Server.Tests;

/// <summary>Pins a server's whole tool surface -- names, descriptions, schemas -- to a golden file.</summary>
/// <remarks>
/// Sorted by name because registration order is not a contract; the content is. Regenerate deliberately
/// with the server's update variable set to 1, and review the diff before committing it.
/// </remarks>
public static class ToolSnapshotGuard
{
    public static void AssertMatchesGolden(IServiceProvider provider, string goldenPath, string updateVariable)
    {
        ArgumentNullException.ThrowIfNull(provider);

        var tools = provider.GetServices<McpServerTool>()
            .Select(tool => tool.ProtocolTool)
            .OrderBy(tool => tool.Name, StringComparer.Ordinal)
            .ToList();
        var actual = JsonSerializer.Serialize(
            tools, new JsonSerializerOptions(McpJsonUtilities.DefaultOptions) { WriteIndented = true }) + "\n";

        if (Environment.GetEnvironmentVariable(updateVariable) == "1")
        {
            Directory.CreateDirectory(Path.GetDirectoryName(goldenPath)!);
            File.WriteAllText(goldenPath, actual);
        }

        Assert.True(File.Exists(goldenPath), $"No snapshot at {goldenPath}. Run once with {updateVariable}=1.");
        Assert.Equal(File.ReadAllText(goldenPath).ReplaceLineEndings("\n"), actual.ReplaceLineEndings("\n"));
    }

    /// <summary>A path under the repository root, found by walking up to the solution file.</summary>
    public static string RepositoryFile(params string[] parts)
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            if (File.Exists(Path.Combine(d.FullName, "WinDiag.Mcp.sln")))
            {
                return Path.Combine([d.FullName, .. parts]);
            }
        }

        throw new InvalidOperationException($"No WinDiag.Mcp.sln above {AppContext.BaseDirectory}.");
    }
}
