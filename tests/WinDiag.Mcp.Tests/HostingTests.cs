using System.Collections;
using System.Text;
using WinDiag.Mcp.Configuration;
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
