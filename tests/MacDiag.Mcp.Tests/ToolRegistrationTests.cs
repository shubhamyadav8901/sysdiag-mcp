using System.Collections;
using MacDiag.Mcp.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;

namespace MacDiag.Mcp.Tests;

public sealed class ToolRegistrationTests
{
    internal static MacDiagOptions Options(bool readOnly = false, bool selfUpdate = false, bool commands = false) =>
        MacDiagOptions.FromEnvironment(new Hashtable
        {
            ["MACDIAG_READ_ONLY"] = readOnly ? "1" : "0",
            ["MACDIAG_ALLOW_SELF_UPDATE"] = selfUpdate ? "1" : "0",
            ["MACDIAG_ALLOW_COMMAND_EXECUTION"] = commands ? "1" : "0"
        });

    internal static ServiceProvider Provider(MacDiagOptions options)
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.ClearProviders());
        ServerBuilder.ConfigureServices(services, options);
        return services.BuildServiceProvider();
    }

    private static string[] ToolNames(MacDiagOptions options)
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

    // GatedToolGuard is not called until plan 3: it requires process_control and service_control, which
    // this server does not have yet. Until then run_command's gating is asserted directly.
    [Fact]
    public void Run_command_is_registered_only_with_its_grant_and_never_on_a_read_only_server()
    {
        Assert.DoesNotContain("run_command", ToolNames(Options()));
        Assert.Contains("run_command", ToolNames(Options(commands: true)));
        Assert.DoesNotContain("run_command", ToolNames(Options(readOnly: true, commands: true)));
    }

    [Fact]
    public void Update_self_is_registered_only_with_its_grant_and_never_on_a_read_only_server()
    {
        Assert.DoesNotContain("update_self", ToolNames(Options()));
        Assert.Contains("update_self", ToolNames(Options(selfUpdate: true)));
        Assert.DoesNotContain("update_self", ToolNames(Options(readOnly: true, selfUpdate: true)));
    }

    [Fact]
    public void The_update_services_are_registered_whatever_the_grant_so_a_test_fake_wins()
    {
        using var provider = Provider(Options());

        Assert.NotNull(provider.GetService<Diag.Mcp.Server.SelfUpdate.IUpdateGuard>());
    }

    [Fact]
    public void The_tool_surface_matches_the_recorded_snapshot()
    {
        using var provider = Provider(Options(selfUpdate: true, commands: true));

        ToolSnapshotGuard.AssertMatchesGolden(
            provider,
            ToolSnapshotGuard.RepositoryFile("tests", "MacDiag.Mcp.Tests", "Fixtures", "tools-list.golden.json"),
            "MACDIAG_UPDATE_TOOL_SNAPSHOT");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Put_file_may_write_into_the_server_directory_only_with_the_self_update_grant(bool selfUpdate)
    {
        // The install directory holds a root daemon's binary. Writing there is staging a build for update_self,
        // so it follows that grant -- and the refusal names the grant's variable as --help spells it.
        using var provider = Provider(Options(selfUpdate: selfUpdate));

        var files = provider.GetRequiredService<Diag.Mcp.Server.Files.FileTransferOptions>();

        Assert.Equal(selfUpdate, files.ServerDirectoryWritable);
        Assert.Equal("MACDIAG_ALLOW_SELF_UPDATE=1", files.ServerDirectorySetting);
        Assert.Contains(files.ServerDirectorySetting!, ServerBuilder.HelpText, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_c_library_import_loads_it_by_its_system_name()
    {
        var checkedImports = NativeImportGuard.AssertEveryImportUsesTheSystemResolver(
            typeof(ServerBuilder).Assembly, typeof(Diag.Mcp.Server.Files.FileTransferOptions).Assembly);

        Assert.True(checkedImports > 0, "The sweep found no P/Invoke; it would pass vacuously.");
    }

    [Fact]
    public void The_server_is_not_built_for_invariant_globalization()
    {
        // FileScope's case/NFC gate on APFS needs real normalisation; invariant mode makes Normalize a silent
        // no-op. The server's runtimeconfig is copied beside the tests, so read what it will run with.
        var config = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "MacDiag.Mcp.runtimeconfig.json"));

        Assert.DoesNotContain("System.Globalization.Invariant\": true", config, StringComparison.Ordinal);
    }
}
