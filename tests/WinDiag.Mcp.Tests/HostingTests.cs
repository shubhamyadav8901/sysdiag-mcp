using System.Collections;
using System.Text;
using WinDiag.Mcp.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Hosting;

namespace WinDiag.Mcp.Tests;

public sealed class BearerTokenGateTests
{
    private static readonly byte[] Expected = Encoding.UTF8.GetBytes("s3cret-token");

    [Fact]
    public void Accepts_the_expected_token()
    {
        Assert.True(BearerTokenGate.IsAuthorized(["Bearer s3cret-token"], Expected));
    }

    [Fact]
    public void Accepts_the_scheme_in_any_case_because_http_says_so()
    {
        Assert.True(BearerTokenGate.IsAuthorized(["bearer s3cret-token"], Expected));
        Assert.True(BearerTokenGate.IsAuthorized(["BEARER s3cret-token"], Expected));
    }

    [Theory]
    [InlineData("Bearer wrong")]
    [InlineData("Bearer S3CRET-TOKEN")]     // the token itself is case-sensitive
    [InlineData("Bearer s3cret-token-plus")]
    [InlineData("Bearer s3cret")]
    [InlineData("Basic s3cret-token")]
    [InlineData("s3cret-token")]
    [InlineData("Bearer ")]
    [InlineData("")]
    public void Rejects_anything_else(string header)
    {
        Assert.False(BearerTokenGate.IsAuthorized([header], Expected));
    }

    [Fact]
    public void Rejects_a_request_with_no_authorization_header()
    {
        Assert.False(BearerTokenGate.IsAuthorized([], Expected));
        Assert.False(BearerTokenGate.IsAuthorized([null], Expected));
    }

    [Fact]
    public void Generates_a_token_with_real_entropy()
    {
        // 256 bits, hex encoded. A short or predictable token here is the whole security boundary
        // failing, since any local user can reach the port.
        var first = BearerTokenGate.GenerateToken();
        var second = BearerTokenGate.GenerateToken();

        Assert.Equal(64, first.Length);
        Assert.NotEqual(first, second);
        Assert.All(first, c => Assert.Contains(c, "0123456789abcdef"));
    }
}

public sealed class CommandLineTests
{
    private static WinDiagOptions Options(string? bind = null)
    {
        var env = new Hashtable();
        if (bind is not null)
        {
            env["WINDIAG_HTTP_BIND"] = bind;
        }

        return WinDiagOptions.FromEnvironment(env);
    }

    [Fact]
    public void No_arguments_means_stdio()
    {
        Assert.Null(CommandLine.ResolveHttpBind([], Options()));
    }

    [Fact]
    public void An_inline_address_selects_http()
    {
        Assert.Equal(
            "http://10.0.0.5:7777",
            CommandLine.ResolveHttpBind(["--http", "http://10.0.0.5:7777"], Options()));
    }

    [Fact]
    public void The_environment_alone_can_select_http()
    {
        // Lets a deployment configure HTTP mode with no command line at all.
        Assert.Equal("http://10.0.0.5:7777", CommandLine.ResolveHttpBind([], Options("http://10.0.0.5:7777")));
    }

    [Fact]
    public void An_inline_address_wins_over_the_environment()
    {
        Assert.Equal(
            "http://127.0.0.1:9000",
            CommandLine.ResolveHttpBind(["--http", "http://127.0.0.1:9000"], Options("http://10.0.0.5:7777")));
    }

    [Fact]
    public void Refuses_to_guess_an_address()
    {
        // No default, deliberately. A server that runs elevated and picks its own bind address is a
        // privilege boundary opened by accident.
        var ex = Assert.Throws<ConfigurationException>(() => CommandLine.ResolveHttpBind(["--http"], Options()));

        Assert.Contains("no default", ex.Message);
    }

    [Fact]
    public void Does_not_treat_a_following_switch_as_the_address()
    {
        Assert.Throws<ConfigurationException>(
            () => CommandLine.ResolveHttpBind(["--http", "--read-only"], Options()));
    }

    [Theory]
    [InlineData("7777")]
    [InlineData("10.0.0.5:7777")]
    [InlineData("ftp://10.0.0.5:7777")]
    public void Rejects_an_address_that_is_not_an_http_url(string address)
    {
        var ex = Assert.Throws<ConfigurationException>(
            () => CommandLine.ResolveHttpBind(["--http", address], Options()));

        Assert.Contains("full URL", ex.Message);
    }

    [Theory]
    [InlineData("http://0.0.0.0:7777")]
    [InlineData("http://*:7777")]
    [InlineData("http://+:7777")]
    [InlineData("http://[::]:7777")]
    [InlineData("http://0:7777")]
    public void Recognises_a_wildcard_bind_so_it_can_be_warned_about(string address)
    {
        Assert.True(CommandLine.IsWildcardBind(address));
    }

    [Theory]
    [InlineData("https://target.contoso.com:7777")]
    [InlineData("http://TARGETVM:7777")]
    public void Treats_a_hostname_as_a_wildcard_because_kestrel_does(string address)
    {
        // The trap: a hostname LOOKS specific, so an operator writing the target's own name believes
        // they have scoped the listener to one interface. Kestrel's binder falls back to its any-IP
        // strategy for any host that is not an IP literal and is not localhost, and the process ends
        // up on 0.0.0.0 — verified by netstat against a real run. On an elevated listener that
        // deserves the warning far more than an explicit 0.0.0.0 does.
        Assert.True(CommandLine.IsWildcardBind(address));
    }

    [Theory]
    [InlineData("http://127.0.0.1:7777")]
    [InlineData("http://10.0.0.5:7777")]
    [InlineData("http://localhost:7777")]
    [InlineData("http://[::1]:7777")]
    public void Does_not_warn_about_a_genuinely_specific_interface(string address)
    {
        Assert.False(CommandLine.IsWildcardBind(address));
    }

    [Fact]
    public void Validates_an_address_that_came_from_the_environment_too()
    {
        // A deployment script is a likelier place for a typo than an interactive command line, so the
        // env path must not be the lenient one.
        var ex = Assert.Throws<ConfigurationException>(
            () => CommandLine.ResolveHttpBind([], Options("10.0.0.5:7777")));

        Assert.Contains("full URL", ex.Message);
    }
}

public sealed class OptionsRedactionTests
{
    [Fact]
    public void Never_writes_the_token_into_the_startup_log()
    {
        // Describe() is logged at startup and could easily end up in a support bundle.
        var env = new Hashtable { ["WINDIAG_TOKEN"] = "super-secret-value" };

        var description = WinDiagOptions.FromEnvironment(env).Describe();

        Assert.DoesNotContain("super-secret-value", description);
        Assert.Contains("(configured)", description);
    }

    [Fact]
    public void Distinguishes_a_configured_token_from_a_generated_one()
    {
        Assert.Contains("(generated)", WinDiagOptions.FromEnvironment(new Hashtable()).Describe());
    }

    [Fact]
    public void Never_leaks_the_token_through_the_default_record_ToString()
    {
        // This type is a record, and a record's generated ToString prints every property. Without the
        // override, any log line or exception message that interpolated the options object would carry
        // the token with it.
        var env = new Hashtable { ["WINDIAG_TOKEN"] = "super-secret-value" };

        Assert.DoesNotContain("super-secret-value", WinDiagOptions.FromEnvironment(env).ToString());
    }

    [Fact]
    public void Reports_the_address_it_was_switched_to_rather_than_stdio()
    {
        // The startup line is the record that survives into a support bundle. Reporting "(stdio)"
        // while a TCP port is open misstates exactly the fact worth reconstructing later.
        var options = WinDiagOptions.FromEnvironment(new Hashtable()) with { HttpBind = "http://10.0.0.5:7777" };

        Assert.Contains("httpBind=http://10.0.0.5:7777", options.Describe());
    }
}

/// <summary>
/// Running under the Service Control Manager is additive, never a change to running from a terminal.
/// </summary>
/// <remarks>
/// windiag exists to be started by hand on a target, and the whole fleet is driven that way today.
/// Service support was added so a target could be restarted remotely rather than needing someone at
/// its console -- but the console and stdio paths had to keep behaving exactly as before, because a
/// regression there breaks every existing deployment at once and would only show up on a target.
/// </remarks>
public sealed class WindowsServiceHostingTests
{
    private static ServiceCollection Configured()
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.ClearProviders());
        ServerBuilder.ConfigureServices(services, WinDiagOptions.FromEnvironment(new Hashtable()));
        return services;
    }

    [Fact]
    public void Does_not_take_over_the_lifetime_when_nobody_started_us_as_a_service()
    {
        // AddWindowsService is guarded on WindowsServiceHelpers.IsWindowsService(), so interactively it
        // must add no service lifetime at all. If it ever did, Ctrl-C would stop working and the process
        // would sit waiting for a stop signal from a Service Control Manager that never sent one -- a
        // server that looks started and answers nothing.
        var lifetimes = Configured()
            .Where(d => d.ServiceType.Name == "IHostLifetime")
            .Select(d => d.ImplementationType?.Name ?? d.ImplementationInstance?.GetType().Name)
            .ToArray();

        Assert.DoesNotContain("WindowsServiceLifetime", lifetimes);
    }

    [Fact]
    public void Still_registers_the_whole_tool_surface_alongside_service_support()
    {
        // The registration order matters only in that nothing may be displaced: service support is a
        // hosting concern and must not disturb the MCP graph it sits next to.
        using var provider = Configured().BuildServiceProvider();

        var tools = provider.GetServices<McpServerTool>().Select(t => t.ProtocolTool.Name).ToArray();

        Assert.Contains("who_locks_path", tools);
        Assert.Contains("capture_activity", tools);
        Assert.NotNull(provider.GetService<ToolActivity>());
    }
}

/// <summary>
/// The event log must never be able to break the thing it is reporting on.
/// </summary>
/// <remarks>
/// A service has no stderr, so logging is redirected to the Windows event log -- and writing there
/// throws when the source is not registered. That turned a log line nobody asked for into a failed
/// update_self on a running service, and it hid well: the provider's minimum level is Warning, so every
/// Information line was filtered and never attempted a write. The server started, served every tool,
/// and only died on the first Warning in its life, which happens to fire halfway through an update.
/// </remarks>
public sealed class EventLogSinkTests
{
    [Fact]
    public void Pins_the_source_name_so_installer_and_server_cannot_drift()
    {
        // The installer registers this name and the server writes to it. Defaulting to the application
        // name would let a rename separate them silently, which is the same failure again.
        Assert.Equal("windiag", EventLogSink.SourceName);
        Assert.Equal("Application", EventLogSink.LogName);
    }

    [Fact]
    public void Does_nothing_interactively_because_the_provider_is_never_added()
    {
        // Run from a terminal, stderr is always writable and AddWindowsService adds no event log
        // provider at all -- so this must not disturb the console logging that is there.
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.ClearProviders().AddConsole());

        var before = services.Count;
        EventLogSink.MakeSafe(services);

        Assert.Equal(before, services.Count);

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetRequiredService<ILoggerFactory>().CreateLogger("x"));
    }

    [Fact]
    public void Registering_the_source_swallows_a_failure_nobody_predicted()
    {
        // FileNotFoundException on purpose: it is outside every list a person would write down, and it
        // is the one that actually happened -- System.Threading.AccessControl missing from the bundle,
        // thrown from inside EventLog, escaping a catch that named only the plausible types and taking
        // --install-service down with an unhandled stack trace.
        //
        // This asserts the return value rather than merely that nothing escaped. A no-throw assertion
        // is unfalsifiable once the catch is broad, and calling the real registration would create an
        // HKLM event source on whichever machine ran the suite elevated -- a test that mutates the
        // developer's machine to prove nothing.
        var registered = EventLogSink.TryRegisterSource(
            () => throw new FileNotFoundException("System.Threading.AccessControl"));

        Assert.False(registered);
    }

    [Fact]
    public void A_source_that_cannot_be_registered_takes_the_sink_out_with_it()
    {
        // The branch the live target never exercised, because registration succeeded there. Without it
        // a service keeps a logger that throws on first write, which is the original bug: every tool
        // works until something logs a warning, and here that is update_self mid-update.
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.ClearProviders().AddEventLog());

        var before = services.Count(Descriptor.IsEventLogProvider);
        EventLogSink.MakeSafe(services, isWindowsService: true, tryRegister: () => false);
        var after = services.Count(Descriptor.IsEventLogProvider);

        // Asserted as a drop, not as "none remain". Matching on ImplementationType is a bet on a BCL
        // detail; if AddEventLog ever registers through a factory the match finds nothing, and a bare
        // "none remain" would pass on a collection where nothing was ever found to remove.
        Assert.Equal(1, before);
        Assert.Equal(0, after);
    }

    [Fact]
    public void A_source_that_registers_keeps_the_sink_and_pins_the_name_it_writes_to()
    {
        // Proves the pinned name actually reaches EventLogSettings. Asserting the constant only proves
        // the constant; what matters is that the name the installer registered and the name the
        // provider writes under are the same string, and that is decided by Configure ordering.
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.ClearProviders().AddEventLog());

        EventLogSink.MakeSafe(services, isWindowsService: true, tryRegister: () => true);

        Assert.Equal(1, services.Count(Descriptor.IsEventLogProvider));

        using var provider = services.BuildServiceProvider();
        var settings = provider.GetRequiredService<IOptions<EventLogSettings>>().Value;

        Assert.Equal(EventLogSink.SourceName, settings.SourceName);
    }

    private static class Descriptor
    {
        public static bool IsEventLogProvider(ServiceDescriptor descriptor) =>
            descriptor.ServiceType == typeof(ILoggerProvider)
            && descriptor.ImplementationType == typeof(EventLogLoggerProvider);
    }
}
