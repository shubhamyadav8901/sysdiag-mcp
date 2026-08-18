using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace WinDiag.Mcp.Relay;

/// <summary>
/// The relay's live connections: one per target VM, each under a short alias.
/// </summary>
/// <remarks>
/// <para>The relay is one stdio MCP server registered once on the base machine, with no address of its
/// own. Each <c>connect</c> points it at a target windiag over HTTP under an alias; the target's tools
/// then appear here prefixed by that alias (<c>web1__process_list</c>), and calls route to the right
/// VM. Several targets can be connected at once, so one registration drives a whole fleet, and a
/// target's address is always runtime data in a tool call, never configuration -- which is what a set
/// of lab VMs on ever-changing IPs needs.</para>
/// <para>Connections are keyed by alias in a dictionary guarded by one lock. A <c>connect</c> or
/// <c>disconnect</c> takes the lock to add or remove; a forwarded call reads its target's client under
/// it, so repointing or dropping one target mid-session never forwards to a half-torn-down client.</para>
/// </remarks>
internal sealed class RelayState : IAsyncDisposable
{
    /// <summary>Separates an alias from the target's own tool name in a listed tool: <c>alias__tool</c>.</summary>
    /// <remarks>
    /// Two underscores, and an alias may not contain them, so the split is unambiguous even though the
    /// target's own tool names (<c>process_list</c>) are full of single underscores.
    /// </remarks>
    public const string AliasSeparator = "__";

    /// <summary>The port a bare host is assumed to serve on, and the one a derived alias omits.</summary>
    public const int DefaultPort = 4024;

    private static readonly Regex AliasPattern = new("^[A-Za-z0-9_-]+$", RegexOptions.Compiled);

    private sealed record Connection(McpClient Client, IReadOnlyList<Tool> Tools, string Target);

    private readonly ILoggerFactory _loggerFactory;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, Connection> _connections = new(StringComparer.OrdinalIgnoreCase);

    public RelayState(ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory;
    }

    public bool AnyConnected
    {
        get
        {
            _gate.Wait();
            try { return _connections.Count > 0; }
            finally { _gate.Release(); }
        }
    }

    /// <summary>A snapshot of each connection, for status.</summary>
    public IReadOnlyList<(string Alias, string Target, int ToolCount)> Connections()
    {
        _gate.Wait();
        try
        {
            return _connections
                .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .Select(pair => (pair.Key, pair.Value.Target, pair.Value.Tools.Count))
                .ToList();
        }
        finally { _gate.Release(); }
    }

    /// <summary>Every connected target's tools, each renamed <c>alias__tool</c> for the dynamic list.</summary>
    public IReadOnlyList<Tool> PrefixedTools()
    {
        _gate.Wait();
        try
        {
            return _connections
                .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .SelectMany(pair => pair.Value.Tools.Select(t => Rename(t, pair.Key)))
                .ToList();
        }
        finally { _gate.Release(); }
    }

    /// <summary>Connects a target under an alias, replacing any connection already under that alias.</summary>
    /// <returns>The alias used and the number of tools the target exposes.</returns>
    public async Task<(string Alias, int ToolCount)> ConnectAsync(
        string alias, string address, string token, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(alias);
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        if (!AliasPattern.IsMatch(alias) || alias.Contains(AliasSeparator, StringComparison.Ordinal))
        {
            throw new RelayException(
                $"'{alias}' is not a usable alias. Use letters, digits, single underscores or hyphens, " +
                "and no double underscore (that separates the alias from the tool name).");
        }

        if (!Uri.TryCreate(address, UriKind.Absolute, out var endpoint) ||
            endpoint.Scheme is not ("http" or "https"))
        {
            throw new RelayException(
                $"'{address}' is not an http(s) URL. Pass the target's windiag address, for example " +
                "http://192.168.32.93:4024.");
        }

        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = endpoint,
            Name = $"windiag-relay/{alias}",
            AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = $"Bearer {token}" }
        });

        McpClient client;
        try
        {
            client = await McpClient.CreateAsync(transport, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        // Cancellation is let through rather than wrapped: the pre-connect budget expiring means "that
        // target did not answer in time", and reporting it as "check the firewall and the token" sends
        // the operator auditing configuration over a VM that is merely switched off.
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new RelayException(
                $"Could not reach a windiag server at {address}: {ex.Message}. Check the target is up, " +
                "the port is right, the firewall allows this machine, and the token matches.", ex);
        }

        List<Tool> tools;
        try
        {
            var listed = await client.ListToolsAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
            tools = listed.Select(t => t.ProtocolTool).ToList();
        }
        catch (Exception ex)
        {
            await DisposeQuietly(client).ConfigureAwait(false);

            if (ex is OperationCanceledException)
            {
                throw;
            }

            throw new RelayException(
                $"Connected to {address} but could not read its tool list: {ex.Message}", ex);
        }

        // The client is fully connected by this point, so anything that throws before it is handed to
        // _connections strands it: nothing disposes it, and the TARGET keeps its session and stream open
        // with no one on the other end. Cancellation here is reachable -- several pre-connects contend
        // for this gate inside one shared budget.
        try
        {
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            await DisposeQuietly(client).ConfigureAwait(false);
            throw;
        }

        try
        {
            if (_connections.TryGetValue(alias, out var existing))
            {
                await DisposeQuietly(existing.Client).ConfigureAwait(false);
            }

            _connections[alias] = new Connection(client, tools, address);
        }
        finally
        {
            _gate.Release();
        }

        return (alias, tools.Count);
    }

    /// <summary>Drops one alias, or every connection when <paramref name="alias"/> is null.</summary>
    /// <returns>The aliases that were dropped.</returns>
    public async Task<IReadOnlyList<string>> DisconnectAsync(string? alias, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var toDrop = alias is null
                ? _connections.Keys.ToList()
                : _connections.Keys.Where(k => k.Equals(alias, StringComparison.OrdinalIgnoreCase)).ToList();

            foreach (var key in toDrop)
            {
                await DisposeQuietly(_connections[key].Client).ConfigureAwait(false);
                _connections.Remove(key);
            }

            return toDrop;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Forwards a call to the target behind <paramref name="alias"/> and returns its result verbatim.</summary>
    public async Task<CallToolResult> ForwardAsync(
        string alias,
        string toolName,
        IReadOnlyDictionary<string, object?>? arguments,
        CancellationToken cancellationToken)
    {
        McpClient client;
        string target;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_connections.TryGetValue(alias, out var connection))
            {
                var known = _connections.Count == 0
                    ? "No targets are connected. Call 'connect' first."
                    : $"Connected aliases: {string.Join(", ", _connections.Keys.OrderBy(k => k))}.";
                throw new RelayException($"No target is connected under alias '{alias}'. {known}");
            }

            client = connection.Client;
            target = connection.Target;
        }
        finally
        {
            _gate.Release();
        }

        var args = arguments?.ToDictionary(pair => pair.Key, pair => pair.Value);

        try
        {
            return await client.CallToolAsync(toolName, args, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not RelayException)
        {
            throw new RelayException(
                $"The call to '{toolName}' on {alias} ({target}) failed: {ex.Message}. If that target " +
                "restarted (an update_self, say), reconnect it and retry.", ex);
        }
    }

    /// <summary>A sensible default alias when the caller does not name one: the host, dots to hyphens.</summary>
    /// <remarks>
    /// A tool name may not contain a dot, so <c>192.168.32.93</c> cannot be an alias as-is; hyphens are
    /// both name-safe and free of the <c>__</c> separator, so <c>192-168-32-93</c> is the derived form.
    /// </remarks>
    public static string DefaultAlias(string address)
    {
        var host = address;
        int? port = null;
        if (Uri.TryCreate(address, UriKind.Absolute, out var uri))
        {
            host = uri.Host;
            port = uri.Port;
        }

        var cleaned = Regex.Replace(host, "[^A-Za-z0-9-]", "-").Trim('-');
        if (string.IsNullOrEmpty(cleaned))
        {
            cleaned = "target";
        }

        // Two servers on one host but different ports would otherwise derive the SAME alias, and
        // pre-connect starts them concurrently: both connect, the later one evicts the earlier under the
        // gate, and which port answers that alias is decided by whichever won the race that boot.
        return port is { } p && p != DefaultPort ? $"{cleaned}-{p}" : cleaned;
    }

    /// <summary>Builds a target URL from a bare host[:port], or passes a full URL through unchanged.</summary>
    /// <remarks>
    /// A bare host is the common case -- the caller has an IP from wherever the VM was assigned one -- so
    /// the relay wraps it in http://host:port. Shared by the connect tool and the targets file so both
    /// derive the same address, and therefore the same default alias, for the same entry.
    /// </remarks>
    public static string BuildAddress(string target, int? port, int defaultPort = DefaultPort) =>
        target.Contains("://", StringComparison.Ordinal)
            ? target
            : $"http://{target}:{port ?? defaultPort}";

    /// <summary>Splits a listed tool name into its alias and the target's own tool name.</summary>
    public static (string Alias, string Tool)? SplitToolName(string listedName)
    {
        var index = listedName.IndexOf(AliasSeparator, StringComparison.Ordinal);
        if (index <= 0 || index + AliasSeparator.Length >= listedName.Length)
        {
            return null;
        }

        return (listedName[..index], listedName[(index + AliasSeparator.Length)..]);
    }

    private static Tool Rename(Tool tool, string alias) => new()
    {
        Name = $"{alias}{AliasSeparator}{tool.Name}",
        Title = tool.Title is { } title ? $"[{alias}] {title}" : $"[{alias}] {tool.Name}",
        Description = tool.Description,
        InputSchema = tool.InputSchema,
        OutputSchema = tool.OutputSchema,
        Annotations = tool.Annotations
    };

    private static async Task DisposeQuietly(McpClient client)
    {
        try { await client.DisposeAsync().ConfigureAwait(false); }
        catch (Exception) { /* tearing down; nothing useful to do */ }
    }

    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            foreach (var connection in _connections.Values)
            {
                await DisposeQuietly(connection.Client).ConfigureAwait(false);
            }

            _connections.Clear();
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
        }
    }

    /// <summary>Builds the JSON input-schema element for a control tool.</summary>
    internal static JsonElement Schema(string json) => JsonSerializer.Deserialize<JsonElement>(json);
}

/// <summary>Raised for a relay-level failure: not connected, an unreachable target, a bad address or alias.</summary>
internal sealed class RelayException : Exception
{
    public RelayException(string message) : base(message)
    {
    }

    public RelayException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
