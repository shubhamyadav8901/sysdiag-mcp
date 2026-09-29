using WinDiag.Mcp.Configuration;

namespace WinDiag.Mcp.Hosting;

/// <summary>Argument parsing for the two ways this server can be started.</summary>
public static class CommandLine
{
    /// <summary>
    /// Decides whether to serve over HTTP, and on what address. Null means stdio.
    /// </summary>
    /// <remarks>
    /// There is no default address. A server that runs elevated on someone's machine and picks its own
    /// bind address is a privilege boundary opened by accident, so <c>--http</c> without an address
    /// and without <c>WINDIAG_HTTP_BIND</c> is a startup failure rather than a guess. The rules
    /// themselves live in <see cref="HttpBind"/>, shared with every server in the family.
    /// </remarks>
    public static string? ResolveHttpBind(IReadOnlyList<string> args, WinDiagOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return HttpBind.Resolve(args, options.HttpBind, "WINDIAG_HTTP_BIND");
    }

    /// <summary>True when the address accepts connections on every network interface.</summary>
    public static bool IsWildcardBind(string address) => HttpBind.IsWildcard(address);

    /// <summary>True when the caller asked for relay mode, which no longer lives in this executable.</summary>
    /// <remarks>
    /// Refused explicitly rather than ignored. Ignored, <c>--relay</c> falls through to stdio mode and
    /// starts a diagnostics server in the relay's place -- a stale MCP registration would then connect
    /// to this machine's own tools instead of the fleet, and nothing would say anything was wrong.
    /// </remarks>
    public static bool AsksForRemovedRelay(IReadOnlyList<string> args) => args.Any(a => a is "--relay");

    public const string RemovedRelayMessage =
        "[windiag] --relay was removed: the relay is now its own executable, DiagRelay.Mcp, published to " +
        "artifacts/diagrelay/. Point your MCP registration at it -- keep the entry name 'windiag' and " +
        "every forwarded tool name stays the same. See the README, under the relay.";
}
