using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;

namespace DiagRelay.Mcp.Tests;

/// <summary>
/// The relay's guards that hold without a live target. The forwarding itself is an integration
/// concern proven against real servers; these pin the refusals a unit test can own.
/// </summary>
public sealed class RelayStateTests
{
    private static RelayState State() => new(NullLoggerFactory.Instance);

    [Fact]
    public void Starts_with_no_connections()
    {
        var state = State();

        Assert.False(state.AnyConnected);
        Assert.Empty(state.Connections());
        Assert.Empty(state.PrefixedTools());
    }

    [Theory]
    [InlineData("not-a-url")]
    [InlineData("192.168.32.93:4024")]   // bare host:port is not an absolute URL
    public async Task Rejects_an_address_that_is_not_an_http_url(string address)
    {
        var ex = await Assert.ThrowsAsync<RelayException>(
            () => State().ConnectAsync("a", address, "token", CancellationToken.None));

        Assert.Contains("http", ex.Message);
    }

    [Fact]
    public async Task Rejects_a_non_http_scheme()
    {
        var ex = await Assert.ThrowsAsync<RelayException>(
            () => State().ConnectAsync("a", "ftp://host/x", "token", CancellationToken.None));

        Assert.Contains("http", ex.Message);
    }

    [Theory]
    [InlineData("has space")]
    [InlineData("bad__alias")]   // the double underscore is the reserved alias/tool separator
    [InlineData("dots.here")]
    public async Task Rejects_an_alias_that_would_break_tool_name_routing(string alias)
    {
        var ex = await Assert.ThrowsAsync<RelayException>(
            () => State().ConnectAsync(alias, "http://host:4024", "token", CancellationToken.None));

        Assert.Contains("alias", ex.Message);
    }

    [Theory]
    [InlineData("", "token")]
    [InlineData("http://host:4024", "")]
    public async Task Requires_both_an_address_and_a_token(string address, string token)
    {
        await Assert.ThrowsAsync<ArgumentException>(
            () => State().ConnectAsync("a", address, token, CancellationToken.None));
    }

    [Fact]
    public async Task Forwarding_to_an_unknown_alias_is_refused_with_guidance()
    {
        var ex = await Assert.ThrowsAsync<RelayException>(
            () => State().ForwardAsync("nope", "process_list", null, CancellationToken.None));

        Assert.Contains("connect", ex.Message);
    }

    [Theory]
    [InlineData("192.168.32.93", "192-168-32-93")]         // dots -> hyphens; a tool name allows no dot
    [InlineData("http://192.168.32.76:4024", "192-168-32-76")]
    [InlineData("host-1", "host-1")]
    public void Derives_a_name_safe_default_alias_from_the_address(string address, string expected)
    {
        Assert.Equal(expected, RelayState.DefaultAlias(address));
    }

    [Theory]
    [InlineData("web1__process_list", "web1", "process_list")]
    [InlineData("192-168-32-93__run_command", "192-168-32-93", "run_command")]
    public void Splits_a_listed_tool_name_at_the_first_double_underscore(string listed, string alias, string tool)
    {
        var split = RelayState.SplitToolName(listed);

        Assert.NotNull(split);
        Assert.Equal(alias, split!.Value.Alias);
        Assert.Equal(tool, split.Value.Tool);
    }

    [Theory]
    [InlineData("process_list")]   // no alias prefix at all
    [InlineData("__process_list")] // empty alias
    public void Returns_no_split_for_a_name_that_is_not_alias_prefixed(string listed)
    {
        Assert.Null(RelayState.SplitToolName(listed));
    }

    [Fact]
    public void Two_servers_on_one_host_but_different_ports_get_different_default_aliases()
    {
        // Sharing an alias meant both pre-connected concurrently and then evicted each other, leaving
        // which port answered that alias decided by whichever won the race that boot.
        var first = RelayState.DefaultAlias("http://10.0.0.5:4024");
        var second = RelayState.DefaultAlias("http://10.0.0.5:4025");

        Assert.NotEqual(first, second);
        Assert.Equal("10-0-0-5", first);            // the default port stays implicit
        Assert.Equal("10-0-0-5-4025", second);
    }

    [Theory]
    [InlineData("192.168.32.93", null, "http://192.168.32.93:4024")]
    [InlineData("192.168.32.93", 9000, "http://192.168.32.93:9000")]
    [InlineData("http://192.168.32.93:4024", null, "http://192.168.32.93:4024")]  // a full URL is untouched
    public void Builds_a_target_url_from_a_bare_host_or_passes_a_url_through(
        string target, int? port, string expected)
    {
        Assert.Equal(expected, RelayState.BuildAddress(target, port));
    }
}

/// <summary>
/// The connect tool's argument parsing. <c>persist</c> gets its own tests because the failure direction
/// is writing a bearer token to disk against an explicit instruction not to.
/// </summary>
public sealed class RelayArgumentTests
{
    private static Dictionary<string, JsonElement> Args(string json) =>
        JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json)!;

    [Fact]
    public void An_absent_flag_is_null_so_the_caller_can_default_it()
    {
        Assert.Null(RelayServer.OptionalBool(Args("""{"target":"host"}"""), "persist"));
        Assert.Null(RelayServer.OptionalBool(null, "persist"));
    }

    [Theory]
    [InlineData("""{"persist":false}""", false)]
    [InlineData("""{"persist":true}""", true)]
    [InlineData("""{"persist":"false"}""", false)]   // a client that stringifies its arguments
    [InlineData("""{"persist":"FALSE"}""", false)]
    [InlineData("""{"persist":"no"}""", false)]
    [InlineData("""{"persist":"0"}""", false)]
    [InlineData("""{"persist":"true"}""", true)]
    public void A_stringified_boolean_is_honoured_rather_than_ignored(string json, bool expected)
    {
        Assert.Equal(expected, RelayServer.OptionalBool(Args(json), "persist"));
    }

    [Theory]
    [InlineData("""{"persist":"maybe"}""")]
    [InlineData("""{"persist":7}""")]
    public void An_unrecognisable_value_is_refused_rather_than_defaulted_to_writing_the_token(string json)
    {
        // Defaulting here would persist a credential the caller may have been trying to keep off disk.
        Assert.Throws<RelayException>(() => RelayServer.OptionalBool(Args(json), "persist"));
    }
}
