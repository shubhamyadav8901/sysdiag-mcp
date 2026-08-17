using Microsoft.Extensions.Logging.Abstractions;
using WinDiag.Mcp.Relay;

namespace WinDiag.Mcp.Tests;

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
}
