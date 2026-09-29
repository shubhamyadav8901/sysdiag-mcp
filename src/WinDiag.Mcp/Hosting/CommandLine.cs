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
    /// and without <c>WINDIAG_HTTP_BIND</c> is a startup failure rather than a guess.
    /// </remarks>
    public static string? ResolveHttpBind(IReadOnlyList<string> args, WinDiagOptions options)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(options);

        var index = -1;
        for (var i = 0; i < args.Count; i++)
        {
            if (string.Equals(args[i], "--http", StringComparison.OrdinalIgnoreCase))
            {
                index = i;
                break;
            }
        }

        if (index < 0)
        {
            // WINDIAG_HTTP_BIND on its own is enough: it lets a deployment configure HTTP mode purely
            // through the environment, with no command line at all. Validated on the same terms as the
            // switch -- a deployment script is the likelier place for a typo, not the less likely.
            if (options.HttpBind is { } fromEnvironment)
            {
                Validate(fromEnvironment);
            }

            return options.HttpBind;
        }

        var inlineAddress = index + 1 < args.Count && !args[index + 1].StartsWith('-')
            ? args[index + 1]
            : null;

        var address = inlineAddress ?? options.HttpBind
            ?? throw new ConfigurationException(
                "--http needs an address, and none was configured. Pass one, for example " +
                "'--http http://10.0.0.5:7777', or set WINDIAG_HTTP_BIND. There is deliberately no " +
                "default: this server runs elevated, so where it listens must be a deliberate choice.");

        Validate(address);
        return address;
    }

    /// <summary>True when the address accepts connections on every network interface.</summary>
    /// <remarks>
    /// <para>The obvious wildcards are only half of it. Kestrel's address binder falls back to its
    /// "any IP" strategy for <strong>any host that is not a parseable IP literal and is not
    /// <c>localhost</c></strong> -- so a DNS name binds every interface. Verified:</para>
    /// <code>
    /// --http http://TARGETVM:7893   ->   netstat: TCP 0.0.0.0:7893 LISTENING
    /// </code>
    /// <para>That is the dangerous case precisely because it looks specific. An operator who writes
    /// the target's hostname reasonably believes they have scoped the listener to one interface, and
    /// on an elevated server that mistake is worth warning about loudly.</para>
    /// </remarks>
    public static bool IsWildcardBind(string address)
    {
        if (!Uri.TryCreate(address, UriKind.Absolute, out var uri))
        {
            return address.Contains('*') || address.Contains('+');
        }

        var host = uri.Host;

        if (host is "*" or "+" or "0.0.0.0" or "[::]" or "::")
        {
            return true;
        }

        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Uri renders IPv6 hosts bracketed; IPAddress.TryParse does not accept the brackets.
        return !System.Net.IPAddress.TryParse(host.Trim('[', ']'), out _);
    }

    private static void Validate(string address)
    {
        if (!Uri.TryCreate(address, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ConfigurationException(
                $"'{address}' is not a usable bind address. Give a full URL including the scheme and " +
                "port, for example 'http://10.0.0.5:7777'.");
        }
    }

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
