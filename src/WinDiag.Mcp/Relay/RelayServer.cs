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
        var port = OptionalInt(args, "port") ?? defaultPort;

        // Accept either a full URL or a bare host[:port]. A bare host is the common case -- the caller
        // has an IP from wherever the VM was assigned one -- so the relay builds the URL around it.
        var address = target.Contains("://", StringComparison.Ordinal)
            ? target
            : $"http://{target}:{port}";

        // The alias names this connection so several targets can be live at once. Default it to the
        // host so a single-target caller need not think about it.
        var alias = OptionalString(args, "as") ?? RelayState.DefaultAlias(address);

        var (used, count) = await state.ConnectAsync(alias, address, token, ct).ConfigureAwait(false);
        await NotifyToolsChanged(ctx, ct).ConfigureAwait(false);

        return Text(
            $"Connected to {address} as '{used}'. Its {count} tools are listed here as " +
            $"{used}{RelayState.AliasSeparator}<tool> and calls forward to it. Connect more targets under " +
            "other aliases to drive several at once; 'connect' the same alias again to repoint it.");
    }

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
                "an IP moves - the address is just this argument.",
            InputSchema = RelayState.Schema("""
                {"type":"object",
                 "properties":{
                   "target":{"type":"string","description":"Target host or IP, or a full http URL, e.g. 192.168.32.93 or http://192.168.32.93:4024"},
                   "token":{"type":"string","description":"The target server's WINDIAG_TOKEN bearer token"},
                   "as":{"type":"string","description":"Alias for this connection, prefixing its tools. Letters, digits, single _ or -, no __. Defaults to the host."},
                   "port":{"type":"integer","description":"Port, if target is a bare host and not the default 4024"}},
                 "required":["target","token"]}
                """)
        };

        yield return new Tool
        {
            Name = DisconnectName,
            Title = "Drop a connected target",
            Description = "Disconnect one target by its alias, or all targets if no alias is given. Their tools stop being listed.",
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
