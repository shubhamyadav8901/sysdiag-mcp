using Diag.Mcp.Server.Capabilities;
using Diag.Mcp.Server.Files;
using Diag.Mcp.Server.SelfUpdate;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;

namespace Diag.Mcp.Server.Tests;

/// <summary>What one call to the kit registers, and what it must leave to the server.</summary>
public sealed class RegistrationTests
{
    private static DiagServerSettings Settings(bool readOnly = false) => new(
        readOnly,
        new FileTransferOptions(Path.GetTempPath(), false, false, "W=1", "R=1"),
        new SelfUpdateOptions(Path.GetTempPath(), TimeSpan.FromSeconds(1)));

    /// <summary>The two services every server supplies itself, faked.</summary>
    private static ServiceCollection Services()
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.ClearProviders());
        services.AddSingleton<ICapabilityReporter>(new NoCapabilities());
        services.AddSingleton<IPrivilegeProbe>(new Elevated());
        return services;
    }

    private static List<string> ToolNames(IServiceProvider provider) =>
        provider.GetServices<McpServerTool>().Select(tool => tool.ProtocolTool.Name).ToList();

    [Fact]
    public void Every_tool_the_kit_registers_is_registered_exactly_once()
    {
        // Review Focus 1: the kit and a server both registering one tool class would list it twice.
        var services = Services();
        services.AddDiagServer(Settings(), out _);

        using var provider = services.BuildServiceProvider();
        var names = ToolNames(provider);

        Assert.Equal(["capabilities", "get_file", "put_file"], names.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void A_read_only_server_does_not_offer_put_file()
    {
        var services = Services();
        services.AddDiagServer(Settings(readOnly: true), out _);

        using var provider = services.BuildServiceProvider();

        Assert.Equal(["capabilities", "get_file"], ToolNames(provider).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void A_fake_registered_first_is_the_one_resolved()
    {
        // Review Focus 2: tests register fakes before the wiring runs, and a kit default must not
        // replace them -- or every test of a gated path would silently exercise the real thing.
        var services = Services();
        var fake = new FakeReceiver();
        services.AddSingleton<IFileReceiver>(fake);
        services.AddDiagServer(Settings(), out _);

        using var provider = services.BuildServiceProvider();

        Assert.Same(fake, provider.GetRequiredService<IFileReceiver>());
    }

    [Fact]
    public void The_activity_tracker_handed_back_is_the_one_registered()
    {
        // The gate counts on the instance handed back; the updater resolves the registered one. Two
        // instances would make the drain wait on a count that is always zero.
        var services = Services();
        services.AddDiagServer(Settings(), out var activity);

        using var provider = services.BuildServiceProvider();

        Assert.Same(activity, provider.GetRequiredService<ToolActivity>());
    }

    private sealed class FakeReceiver : IFileReceiver
    {
        public FileWriteResult Receive(FileWriteRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class NoCapabilities : ICapabilityReporter
    {
        public IReadOnlyList<ToolCapability> Describe() => [];
    }

    private sealed class Elevated : IPrivilegeProbe
    {
        public bool IsElevated => true;
    }
}
