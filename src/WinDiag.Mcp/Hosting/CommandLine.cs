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

    // Install options a by-hand server does not take, with the variable that does the same job. A server
    // started by hand reads its grants from the environment only, so `--read-only` here used to be
    // dropped without a word and the server ran writable.
    private static readonly Dictionary<string, string> InstallOnlyOptions = new(StringComparer.OrdinalIgnoreCase)
    {
        ["--read-only"] = "WINDIAG_READ_ONLY=1",
        ["--allow-self-update"] = "WINDIAG_ALLOW_SELF_UPDATE=1",
        ["--allow-command-execution"] = "WINDIAG_ALLOW_COMMAND_EXECUTION=1",
        ["--allow-arbitrary-write"] = "WINDIAG_ALLOW_ARBITRARY_WRITE=1",
        ["--allow-arbitrary-read"] = "WINDIAG_ALLOW_ARBITRARY_READ=1",
        ["--artifacts"] = "WINDIAG_ARTIFACT_DIR",
        ["--token"] = "WINDIAG_TOKEN",
        ["--token-stdin"] = "WINDIAG_TOKEN",
    };

    /// <summary>
    /// Refuses any argument a server started by hand does not understand: it takes <c>--http</c>, with
    /// or without an address, and nothing else.
    /// </summary>
    /// <remarks>
    /// The address after <c>--http</c> is recognised by the same rule <see cref="HttpBind"/> uses -- the
    /// next argument, unless it starts with a dash -- so the two can never disagree about which word
    /// was the address and which an option.
    /// </remarks>
    public static void RejectUnknownServerArguments(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        for (var i = 0; i < args.Count; i++)
        {
            var argument = args[i];
            if (string.Equals(argument, "--http", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < args.Count && !args[i + 1].StartsWith('-'))
                {
                    i++;
                }

                continue;
            }

            if (InstallOnlyOptions.TryGetValue(argument, out var variable))
            {
                throw new ConfigurationException(
                    $"'{argument}' is an --install-service option. A server started by hand takes it from "
                    + $"the environment instead: set {variable}. Refusing to start rather than run without it.");
            }

            throw new ConfigurationException(
                $"'{argument}' is not an argument this server understands"
                + $"{ServiceInstallOptions.Suggest(argument, ["--http", .. InstallOnlyOptions.Keys, .. ServiceInstallOptions.Commands])}. "
                + "Started by hand it takes only '--http <address>'; its settings come from WINDIAG_* "
                + "variables. Run --help for both.");
        }
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
