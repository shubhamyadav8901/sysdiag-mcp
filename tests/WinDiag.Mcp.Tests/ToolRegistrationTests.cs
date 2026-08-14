using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;
using WinDiag.Mcp;
using WinDiag.Mcp.Configuration;

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

    private static WinDiagOptions Options(bool readOnly = false, bool allowSelfUpdate = false) =>
        WinDiagOptions.FromEnvironment(new System.Collections.Hashtable
        {
            ["WINDIAG_READ_ONLY"] = readOnly ? "1" : "0",
            ["WINDIAG_ALLOW_SELF_UPDATE"] = allowSelfUpdate ? "1" : "0"
        });

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
}
