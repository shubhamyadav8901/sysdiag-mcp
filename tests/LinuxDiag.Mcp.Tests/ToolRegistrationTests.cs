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

    [Fact]
    public void The_gated_tools_follow_their_grants()
    {
        GatedToolGuard.AssertGatedToolsFollowTheirGrants(
            (readOnly, selfUpdate, commands) => ToolNames(Options(readOnly, selfUpdate, commands)));
    }

    [Fact]
    public void The_tool_surface_matches_the_recorded_snapshot()
    {
        using var provider = Provider(Options(selfUpdate: true, commands: true));

        ToolSnapshotGuard.AssertMatchesGolden(
            provider,
            ToolSnapshotGuard.RepositoryFile("tests", "LinuxDiag.Mcp.Tests", "Fixtures", "tools-list.golden.json"),
            "LINUXDIAG_UPDATE_TOOL_SNAPSHOT");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Put_file_may_write_into_the_server_directory_only_with_the_self_update_grant(bool selfUpdate)
    {
        // /opt/linuxdiag holds a root service's binary. Writing there is staging a build for update_self,
        // so it follows that grant -- and the refusal names the grant's variable as --help spells it.
        using var provider = Provider(Options(selfUpdate: selfUpdate));

        var files = provider.GetRequiredService<Diag.Mcp.Server.Files.FileTransferOptions>();

        Assert.Equal(selfUpdate, files.ServerDirectoryWritable);
        Assert.Equal("LINUXDIAG_ALLOW_SELF_UPDATE=1", files.ServerDirectorySetting);
        Assert.Contains(files.ServerDirectorySetting!, ServerBuilder.HelpText, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_c_library_import_loads_it_by_its_system_name()
    {
        var checkedImports = NativeImportGuard.AssertEveryImportUsesTheSystemResolver(
            typeof(ServerBuilder).Assembly, typeof(Diag.Mcp.Server.Files.FileTransferOptions).Assembly);

        Assert.True(checkedImports > 0, "The sweep found no P/Invoke; it would pass vacuously.");
    }
}
