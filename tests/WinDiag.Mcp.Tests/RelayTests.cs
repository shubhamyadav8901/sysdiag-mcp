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
    public void Starts_disconnected()
    {
        var state = State();

        Assert.False(state.IsConnected);
        Assert.Null(state.Target);
        Assert.Empty(state.RemoteTools);
    }

    [Theory]
    [InlineData("not-a-url")]
    [InlineData("192.168.32.93:4024")]   // bare host:port is not an absolute URL
    public async Task Rejects_an_address_that_is_not_an_http_url(string address)
    {
        var ex = await Assert.ThrowsAsync<RelayException>(
            () => State().ConnectAsync(address, "token", CancellationToken.None));

        Assert.Contains("http", ex.Message);
    }

    [Fact]
    public async Task Rejects_a_non_http_scheme()
    {
        var ex = await Assert.ThrowsAsync<RelayException>(
            () => State().ConnectAsync("ftp://host/x", "token", CancellationToken.None));

        Assert.Contains("http", ex.Message);
    }

    [Theory]
    [InlineData("", "token")]
    [InlineData("http://host:4024", "")]
    public async Task Requires_both_an_address_and_a_token(string address, string token)
    {
        await Assert.ThrowsAsync<ArgumentException>(
            () => State().ConnectAsync(address, token, CancellationToken.None));
    }

    [Fact]
    public async Task Forwarding_before_connecting_is_refused_with_guidance()
    {
        var ex = await Assert.ThrowsAsync<RelayException>(
            () => State().ForwardAsync("process_list", null, CancellationToken.None));

        Assert.Contains("connect", ex.Message);
    }
}
