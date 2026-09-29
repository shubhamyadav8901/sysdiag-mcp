using System.Text;

namespace Diag.Mcp.Server.Tests;

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
