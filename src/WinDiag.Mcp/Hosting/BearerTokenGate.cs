using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace WinDiag.Mcp.Hosting;

/// <summary>
/// Rejects HTTP requests that do not carry the expected bearer token.
/// </summary>
/// <remarks>
/// <para>The threat model is not only the network. This server runs elevated on the target machine, so
/// <em>any local unprivileged user</em> can reach a bound port; with the token they get SYSTEM-level
/// command execution through a tool call. The token is therefore the only thing standing between an
/// ordinary local account and full control of the box.</para>
/// <para>Comparison is fixed-time. A naive string compare leaks the token a byte at a time to anyone
/// who can time requests, and a local attacker can time them very precisely.</para>
/// </remarks>
public sealed class BearerTokenGate
{
    private const string Scheme = "Bearer ";

    private readonly RequestDelegate _next;
    private readonly byte[] _expected;

    public BearerTokenGate(RequestDelegate next, string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        _next = next;
        _expected = Encoding.UTF8.GetBytes(token);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!IsAuthorized(context.Request.Headers.Authorization, _expected))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.WWWAuthenticate = "Bearer";
            await context.Response.WriteAsync("Missing or invalid bearer token.");
            return;
        }

        await _next(context);
    }

    /// <summary>Validates an Authorization header value against the expected token.</summary>
    /// <remarks>Internal and pure so the rejection rules can be tested without an HTTP stack.</remarks>
    internal static bool IsAuthorized(IEnumerable<string?> authorizationHeaders, byte[] expected)
    {
        foreach (var header in authorizationHeaders)
        {
            if (header is null || !header.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var presented = Encoding.UTF8.GetBytes(header[Scheme.Length..].Trim());

            // FixedTimeEquals already handles unequal lengths without an early return.
            if (CryptographicOperations.FixedTimeEquals(presented, expected))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Creates a token with 256 bits of entropy, URL-safe so it survives copy and paste.</summary>
    public static string GenerateToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
}
