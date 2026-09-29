using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Server;
using WinDiag.Mcp;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Hosting;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// What the server offers under each combination of the two gates.
/// </summary>
/// <remarks>
/// The protocol tests already assert the full tool surface, but only for the default configuration --
/// they spawn a real process, so they cannot cheaply vary the options. These read the registration
/// directly, which is where a mis-gated tool actually lives.
/// </remarks>
public sealed class ToolRegistrationTests
{
    private static string[] ToolNames(WinDiagOptions options)
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.ClearProviders());
        ServerBuilder.ConfigureServices(services, options);

        using var provider = services.BuildServiceProvider();

        return provider.GetServices<McpServerTool>()
            .Select(tool => tool.ProtocolTool.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();
    }

    private static WinDiagOptions Options(
        bool readOnly = false, bool allowSelfUpdate = false, bool allowCommands = false) =>
        WinDiagOptions.FromEnvironment(new System.Collections.Hashtable
        {
            ["WINDIAG_READ_ONLY"] = readOnly ? "1" : "0",
            ["WINDIAG_ALLOW_SELF_UPDATE"] = allowSelfUpdate ? "1" : "0",
            ["WINDIAG_ALLOW_COMMAND_EXECUTION"] = allowCommands ? "1" : "0"
        });

    [Fact]
    public void The_gated_tools_follow_their_grants()
    {
        Diag.Mcp.Server.Tests.GatedToolGuard.AssertGatedToolsFollowTheirGrants(
            (readOnly, selfUpdate, commands) => ToolNames(Options(readOnly, selfUpdate, commands)));
    }

    [Fact]
    public void Shares_one_activity_tracker_between_the_gate_and_the_updater()
    {
        // update_self waits on the count the call-tool filter maintains, so both must be talking about
        // the same object. Two instances would not fail anything loudly: the count the updater watches
        // would simply always be zero, the drain would return instantly, and updates would go back to
        // truncating work exactly as they did before -- green suite and all. That is the same shape of
        // silent regression that let the null-property fix be deleted unnoticed.
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.ClearProviders());
        ServerBuilder.ConfigureServices(services, Options(allowSelfUpdate: true));

        using var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetService<ToolActivity>());
        Assert.Same(provider.GetRequiredService<ToolActivity>(), provider.GetRequiredService<ToolActivity>());

        // And that the gate is actually ON the pipeline. Registering the singleton without the filter
        // would leave the count permanently zero, so the drain would return instantly and updates would
        // silently truncate work again -- with nothing failing. Two filters: readable tool errors, and
        // the activity gate. They compose rather than replacing one another.
        var filters = provider.GetRequiredService<IOptions<McpServerOptions>>()
            .Value.Filters.Request.CallToolFilters;

        Assert.Equal(2, filters.Count);
    }

    [Fact]
    public void Registers_each_tool_exactly_once()
    {
        // A tool registered twice appears twice in tools/list. Clients differ on what they do with a
        // duplicate name, and none of the answers is one this server should be relying on.
        var names = ToolNames(Options(allowSelfUpdate: true));

        Assert.Equal(names.Distinct(StringComparer.Ordinal).ToArray(), names);
    }

    [Fact]
    public void Drops_the_state_changing_tools_in_read_only_mode()
    {
        // Not registered rather than registered-and-refusing: a read-only server should not advertise
        // what it will not do, or a caller plans around a capability that is not there.
        var names = ToolNames(Options(readOnly: true));

        Assert.DoesNotContain("process_control", names);
        Assert.DoesNotContain("service_control", names);
        Assert.DoesNotContain("capture_dump", names);
        Assert.DoesNotContain("capture_activity", names);

        // The read-only tools are all still there.
        Assert.Contains("who_locks_path", names);
        Assert.Contains("process_modules", names);
        Assert.Contains("query_activity", names);

        // Including the read side of the file transfer. put_file goes, because writing is a state
        // change; get_file stays, because collecting an artifact off a machine is a read -- and a
        // read-only server is exactly where someone doing that is likely to be pointed. What bounds it
        // is the directory confinement, not the mode.
        Assert.DoesNotContain("put_file", names);
        Assert.Contains("get_file", names);
    }

    [Fact]
    public void Keeps_update_self_off_unless_it_is_asked_for()
    {
        Assert.DoesNotContain("update_self", ToolNames(Options()));
        Assert.Contains("update_self", ToolNames(Options(allowSelfUpdate: true)));
    }

    [Fact]
    public void Refuses_update_self_in_read_only_mode_even_when_allowed()
    {
        // Replacing the server's own elevated binary is the largest change this server can make, so
        // read-only wins over the self-update grant rather than the other way round.
        Assert.DoesNotContain("update_self", ToolNames(Options(readOnly: true, allowSelfUpdate: true)));
    }

    [Fact]
    public void Keeps_run_command_off_unless_it_is_asked_for()
    {
        // The default server is not a shell. run_command turns the bearer token into arbitrary code
        // execution, so it must never appear without the deployment explicitly granting it.
        Assert.DoesNotContain("run_command", ToolNames(Options()));
        Assert.DoesNotContain("run_command", ToolNames(Options(allowSelfUpdate: true)));
        Assert.Contains("run_command", ToolNames(Options(allowCommands: true)));
    }

    [Fact]
    public void Refuses_run_command_in_read_only_mode_even_when_allowed()
    {
        // A read-only server must never be a shell, whatever else it was granted -- the same
        // precedence update_self follows.
        Assert.DoesNotContain("run_command", ToolNames(Options(readOnly: true, allowCommands: true)));
    }

    [Fact]
    public void Offers_put_file_on_a_writable_server_with_no_flag()
    {
        // Unlike run_command and update_self, put_file needs no opt-in: confined to windiag's own
        // directories it grants nothing new, and its point is to remove SMB from staging. The
        // arbitrary-write flag only widens where it may write, which is a call-time decision, not a
        // registration one.
        Assert.Contains("put_file", ToolNames(Options()));
    }

    [Fact]
    public void Drops_put_file_in_read_only_mode()
    {
        // Writing a file is a state change, so a read-only server does not offer it -- the same rule
        // capture_dump and the control tools follow.
        Assert.DoesNotContain("put_file", ToolNames(Options(readOnly: true)));
    }
}
