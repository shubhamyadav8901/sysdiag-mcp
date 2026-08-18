using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace WinDiag.Mcp.Relay;

/// <summary>
/// A local stdio MCP server that forwards to whichever target windiag it is pointed at.
/// </summary>
/// <remarks>
/// Registered once in Claude Code as a plain stdio command with no address, so its registration never
/// changes. It exposes three control tools of its own -- <c>connect</c>, <c>disconnect</c>,
/// <c>status</c> -- and, once connected, the full live tool set of the target it is pointed at, which
/// it mirrors and forwards. Repointing at a new IP is another <c>connect</c> call, not a config edit or
/// a restart, which is exactly what a fleet of lab VMs on ever-changing addresses needs.
///
/// <para>The tool list is dynamic, so after a connect (or disconnect) the relay sends
/// <c>notifications/tools/list_changed</c> and the client re-fetches -- the target's tools appear and
/// disappear as if it were connected directly.</para>
/// </remarks>
public static class RelayServer
{
    private const string ConnectName = "connect";
    private const string DisconnectName = "disconnect";
    private const string StatusName = "status";

    /// <summary>
    /// The whole time budget for pre-connecting the targets file, awaited before the host answers.
    /// A target that is off is the normal case for a fleet of lab VMs, so pre-connect must never hold
    /// the MCP handshake open for long; whatever does not connect inside this window is skipped with a
    /// logged retry line, and the relay comes up with the control tools regardless.
    /// </summary>
    private static readonly TimeSpan PreConnectBudget = TimeSpan.FromSeconds(5);

    public static async Task<int> RunAsync(int defaultPort)
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);

        var loggerFactory = LoggerFactory.Create(b =>
        {
            b.ClearProviders();
            b.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);
        });
        var state = new RelayState(loggerFactory);

        builder.Services.AddMcpServer(options =>
            {
                options.ServerInfo = new Implementation { Name = "windiag-relay", Version = "1.0.0" };
            })
            .WithStdioServerTransport()
            .WithListToolsHandler((ctx, ct) => ListTools(state, ct))
            .WithCallToolHandler((ctx, ct) => CallTool(state, defaultPort, ctx, ct));

        var host = builder.Build();

        // Pre-connect the targets file before the host answers, so the very first tools/list a client
        // enumerates already carries each target's alias__tool tools. This is awaited in full -- firing
        // it in the background would let the first tools/list race a half-populated connection set and
        // enumerate one VM instead of two. Bounded so an off target cannot stall the handshake.
        await PreConnectAsync(state, defaultPort).ConfigureAwait(false);

        Console.Error.WriteLine(
            "[windiag-relay] stdio relay started. Call 'connect' with a target windiag address and token; " +
            "its tools then appear here and calls forward to it. 'connect' again to repoint.");

        await host.RunAsync().ConfigureAwait(false);
        await state.DisposeAsync().ConfigureAwait(false);
        return 0;
    }

    private static ValueTask<ListToolsResult> ListTools(RelayState state, CancellationToken ct)
    {
        var tools = new List<Tool>(ControlTools());
        tools.AddRange(state.PrefixedTools());
        return ValueTask.FromResult(new ListToolsResult { Tools = tools });
    }

    private static async ValueTask<CallToolResult> CallTool(
        RelayState state,
        int defaultPort,
        RequestContext<CallToolRequestParams> ctx,
        CancellationToken ct)
    {
        var name = ctx.Params?.Name ?? string.Empty;
        var args = ctx.Params?.Arguments;

        try
        {
            switch (name)
            {
                case ConnectName:
                    return await Connect(state, defaultPort, ctx, args, ct).ConfigureAwait(false);

                case DisconnectName:
                    var requested = OptionalString(args, "alias");
                    var dropped = await state.DisconnectAsync(requested, ct).ConfigureAwait(false);
                    await NotifyToolsChanged(ctx, ct).ConfigureAwait(false);
                    return Text(dropped.Count == 0
                        ? (requested is null ? "No targets were connected." : $"No target was connected under '{requested}'.")
                        : $"Disconnected: {string.Join(", ", dropped)}. Those targets' tools are no longer listed.");

                case StatusName:
                    var connections = state.Connections();
                    return Text(connections.Count == 0
                        ? "No targets connected. Call 'connect' with a target address and token."
                        : "Connected targets:\n" + string.Join("\n", connections.Select(c =>
                            $"  {c.Alias} -> {c.Target} ({c.ToolCount} tools, listed as {c.Alias}{RelayState.AliasSeparator}*)")));

                default:
                    // Anything else is a target tool, named alias__tool. Split off the alias and forward
                    // the target's own tool name to that connection.
                    var split = RelayState.SplitToolName(name);
                    if (split is not { } routed)
                    {
                        throw new RelayException(
                            $"'{name}' is not a known tool. A target's tools are listed as " +
                            $"alias{RelayState.AliasSeparator}tool once you connect that target.");
                    }

                    var forwardArgs = args?.ToDictionary(p => p.Key, p => (object?)p.Value);
                    return await state.ForwardAsync(routed.Alias, routed.Tool, forwardArgs, ct).ConfigureAwait(false);
            }
        }
        catch (RelayException ex)
        {
            // The custom call handler bypasses the tool-error filter, so relay failures are turned into
            // a readable IsError result here rather than surfacing as a bare protocol error.
            return new CallToolResult
            {
                IsError = true,
                Content = [new TextContentBlock { Text = Describe(ex) }]
            };
        }
    }

    private static async ValueTask<CallToolResult> Connect(
        RelayState state,
        int defaultPort,
        RequestContext<CallToolRequestParams> ctx,
        IDictionary<string, JsonElement>? args,
        CancellationToken ct)
    {
        var target = RequireString(args, "target");
        var token = RequireString(args, "token");

        var address = RelayState.BuildAddress(target, OptionalInt(args, "port"), defaultPort);

        // The alias names this connection so several targets can be live at once. Default it to the
        // host so a single-target caller need not think about it.
        var alias = OptionalString(args, "as") ?? RelayState.DefaultAlias(address);

        var (used, count) = await state.ConnectAsync(alias, address, token, ct).ConfigureAwait(false);
        await NotifyToolsChanged(ctx, ct).ConfigureAwait(false);

        // Only reached once the connect succeeded, so a wrong token (which 401s above) never writes a
        // dud entry to the file. Persist so a relay restart pre-connects this target and its tools are
        // callable from the first tools/list - which is the fix for a client that only reads the tool
        // list at startup and so cannot see a target connected mid-session.
        var persist = OptionalBool(args, "persist") ?? true;
        var sep = RelayState.AliasSeparator;

        return Text(
            $"Connected to {address} as '{used}'. Its {count} tools forward as {used}{sep}<tool>. " +
            Persisted(used, address, token, persist) + "\n" +
            $"If {used}{sep}* are not callable yet, this client only reads its tool list at startup: " +
            "reconnect windiag (/mcp) or start a fresh session and they will be pre-connected. " +
            "Connect more targets under other aliases to drive several at once; connect the same alias to repoint.");
    }

    /// <summary>Saves a just-connected target to the targets file, or explains why it could not.</summary>
    private static string Persisted(string alias, string address, string token, bool persist)
    {
        if (!persist)
        {
            return "Not saved to the targets file (persist=false), so it lasts only until the relay restarts.";
        }

        var path = RelayTargetsFile.DefaultPath();
        try
        {
            RelayTargetsFile.Upsert(path, new RelayTargetEntry(alias, address, token, null));
            return $"Saved to {path} (its bearer token included), so a restart pre-connects it.";
        }
        catch (RelayException ex)
        {
            // Parse failed: the file is malformed, so it was NOT overwritten - and the same broken file
            // means pre-connect is already skipping every target in it. Say that, not a vague "could not save".
            return $"NOT saved: {path} is malformed ({Describe(ex)}) and is left untouched rather than " +
                   $"overwritten. Fix it -- or delete it and let the last good copy at {path}{".bak"} take " +
                   "over -- or pre-connect will keep skipping every target in it. This connection still " +
                   "works for the rest of this session.";
        }
        catch (Exception ex)
        {
            return $"Could not save it to {path} ({Describe(ex)}); it works this session, but add it there " +
                   "by hand so a restart pre-connects it.";
        }
    }

    /// <summary>
    /// Connects every target listed in the targets file, within one shared time budget, before the host
    /// starts. Absent file means nothing to do; a malformed one is logged and skipped so a typo never
    /// costs the operator the control tools; an unreachable target is logged with the call to retry it.
    /// </summary>
    private static async Task PreConnectAsync(RelayState state, int defaultPort)
    {
        var path = RelayTargetsFile.DefaultPath();

        IReadOnlyList<RelayTargetEntry>? entries;
        try
        {
            entries = RelayTargetsFile.Load(path);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[windiag-relay] ignoring the targets file {path}: {Describe(ex)} " +
                "Starting with no pre-connected targets; use 'connect' to add them.");
            return;
        }

        if (entries is null || entries.Count == 0)
        {
            return;
        }

        // Two entries can occupy one alias -- most easily by both omitting "as" on the same host. Started
        // concurrently they would both connect and then evict each other under the state lock, leaving
        // which one answers that alias decided by a race. Resolve it here, deterministically and out loud.
        var deduplicated = new List<RelayTargetEntry>(entries.Count);
        foreach (var entry in entries)
        {
            var alias = RelayTargetsFile.EffectiveAlias(entry);
            var clash = deduplicated.FindIndex(
                e => string.Equals(RelayTargetsFile.EffectiveAlias(e), alias, StringComparison.OrdinalIgnoreCase));

            if (clash >= 0)
            {
                Console.Error.WriteLine(
                    $"[windiag-relay] WARNING: two targets in {path} both resolve to alias '{alias}' " +
                    $"({deduplicated[clash].Target} and {entry.Target}). Using the later one; give them " +
                    "distinct \"as\" values so this is not decided for you.");
                deduplicated[clash] = entry;
            }
            else
            {
                deduplicated.Add(entry);
            }
        }

        Console.Error.WriteLine(
            $"[windiag-relay] pre-connecting {deduplicated.Count} target(s) from {path} " +
            $"(up to {PreConnectBudget.TotalSeconds:0}s)...");

        using var budget = new CancellationTokenSource(PreConnectBudget);
        await Task.WhenAll(deduplicated.Select(entry => PreConnectOneAsync(state, entry, defaultPort, budget.Token)))
            .ConfigureAwait(false);
    }

    /// <summary>Connects one target, turning any failure into a logged retry line rather than a throw.</summary>
    private static async Task PreConnectOneAsync(
        RelayState state, RelayTargetEntry entry, int defaultPort, CancellationToken ct)
    {
        var address = RelayState.BuildAddress(entry.Target, entry.Port, defaultPort);
        var alias = RelayTargetsFile.EffectiveAlias(entry);

        try
        {
            var (used, count) = await state.ConnectAsync(alias, address, entry.Token, ct).ConfigureAwait(false);
            Console.Error.WriteLine($"[windiag-relay] pre-connected {address} as '{used}' ({count} tools).");
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine(
                $"[windiag-relay] pre-connect to {address} (as '{alias}') timed out. " +
                $"Retry once it is up with: connect target={entry.Target} token=<token>{AsArgument(entry)}.");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[windiag-relay] could not pre-connect {address} (as '{alias}'): {Describe(ex)} " +
                $"Retry with: connect target={entry.Target} token=<token>{AsArgument(entry)}.");
        }
    }

    private static string AsArgument(RelayTargetEntry entry) =>
        entry.As is null ? string.Empty : $" as={entry.As}";

    /// <summary>Tells the client the tool list changed so it re-fetches after a connect or disconnect.</summary>
    private static async ValueTask NotifyToolsChanged(RequestContext<CallToolRequestParams> ctx, CancellationToken ct)
    {
        if (ctx.Server is { } server)
        {
            await server.SendNotificationAsync("notifications/tools/list_changed", ct).ConfigureAwait(false);
        }
    }

    private static IEnumerable<Tool> ControlTools()
    {
        yield return new Tool
        {
            Name = ConnectName,
            Title = "Point the relay at a target windiag",
            Description =
                "Connect to a windiag server on a target machine so its tools appear here and calls " +
                "forward to it. Pass target as the host or IP (or a full http URL) and token as its " +
                "bearer token. Its tools are listed as <alias>__<tool> - the alias defaults to the host, " +
                "or set 'as' to name it. Connect several targets under different aliases to drive them " +
                "at once; connect the same alias again to repoint it. No restart or config change when " +
                "an IP moves - the address is just this argument. On success the target (with its token) " +
                "is saved to the targets file so a session restart pre-connects it; if this client will " +
                "not make the <alias>__* tools callable now, reconnect or start a fresh session and they " +
                "will be there. Pass persist=false for a one-off connection you do not want written to disk.",
            InputSchema = RelayState.Schema("""
                {"type":"object",
                 "properties":{
                   "target":{"type":"string","description":"Target host or IP, or a full http URL, e.g. 192.168.32.93 or http://192.168.32.93:4024"},
                   "token":{"type":"string","description":"The target server's WINDIAG_TOKEN bearer token"},
                   "as":{"type":"string","description":"Alias for this connection, prefixing its tools. Letters, digits, single _ or -, no __. Defaults to the host."},
                   "port":{"type":"integer","description":"Port, if target is a bare host and not the default 4024"},
                   "persist":{"type":"boolean","description":"Save this target (with its token) to the targets file so a restart pre-connects it. Default true; set false for a one-off connection."}},
                 "required":["target","token"]}
                """)
        };

        yield return new Tool
        {
            Name = DisconnectName,
            Title = "Drop a connected target",
            Description = "Disconnect one target by its alias, or all targets if no alias is given. Their tools stop " +
                "being listed. This is session-only and does NOT edit the targets file - the file is the durable " +
                "pre-connect set, so a target you drop here comes back on the next restart unless you remove it there.",
            InputSchema = RelayState.Schema("""
                {"type":"object",
                 "properties":{"alias":{"type":"string","description":"Alias to drop; omit to disconnect every target"}}}
                """)
        };

        yield return new Tool
        {
            Name = StatusName,
            Title = "Which targets the relay is pointed at",
            Description = "List every connected target: its alias, address, and how many tools it is forwarding.",
            InputSchema = RelayState.Schema("""{"type":"object","properties":{}}""")
        };
    }

    private static string RequireString(IDictionary<string, JsonElement>? args, string key)
    {
        if (args is not null && args.TryGetValue(key, out var value) && value.ValueKind == JsonValueKind.String)
        {
            var s = value.GetString();
            if (!string.IsNullOrWhiteSpace(s))
            {
                return s;
            }
        }

        throw new RelayException($"'{key}' is required. Call connect with both target and token.");
    }

    private static string? OptionalString(IDictionary<string, JsonElement>? args, string key)
    {
        if (args is not null && args.TryGetValue(key, out var value) && value.ValueKind == JsonValueKind.String)
        {
            var s = value.GetString();
            if (!string.IsNullOrWhiteSpace(s))
            {
                return s.Trim();
            }
        }

        return null;
    }

    private static int? OptionalInt(IDictionary<string, JsonElement>? args, string key)
    {
        if (args is not null && args.TryGetValue(key, out var value) && value.ValueKind == JsonValueKind.Number
            && value.TryGetInt32(out var n))
        {
            return n;
        }

        return null;
    }

    /// <summary>Reads an optional boolean, accepting the stringified form some clients send.</summary>
    /// <remarks>
    /// Strictly matching only JSON true/false would treat <c>"persist": "false"</c> as absent and fall
    /// back to the default -- writing a bearer token to disk against an explicit instruction not to. The
    /// failure direction decides the design: anything that is not recognisably a boolean is refused
    /// rather than defaulted.
    /// </remarks>
    internal static bool? OptionalBool(IDictionary<string, JsonElement>? args, string key)
    {
        if (args is null || !args.TryGetValue(key, out var value))
        {
            return null;
        }

        switch (value.ValueKind)
        {
            case JsonValueKind.True:
            case JsonValueKind.False:
                return value.GetBoolean();

            case JsonValueKind.Null:
            case JsonValueKind.Undefined:
                return null;

            case JsonValueKind.String:
                var text = value.GetString();
                if (string.IsNullOrWhiteSpace(text))
                {
                    return null;
                }

                switch (text.Trim().ToLowerInvariant())
                {
                    case "true" or "yes" or "1" or "on":
                        return true;
                    case "false" or "no" or "0" or "off":
                        return false;
                }

                break;
        }

        throw new RelayException(
            $"'{key}' must be true or false, but was {value.ToString()}. Refusing rather than assuming, " +
            "because the default would write this target's token to the targets file.");
    }

    private static CallToolResult Text(string message) =>
        new() { Content = [new TextContentBlock { Text = message }] };

    private static string Describe(Exception ex)
    {
        var messages = new List<string>();
        for (var current = ex; current is not null; current = current.InnerException)
        {
            var m = current.Message?.Trim();
            if (!string.IsNullOrEmpty(m) && !messages.Any(e => e.Contains(m, StringComparison.Ordinal)))
            {
                messages.Add(m);
            }
        }

        return messages.Count == 0 ? ex.GetType().Name : string.Join(" ", messages);
    }
}
