using System.Text.Json;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace WinDiag.Mcp.Relay;

/// <summary>
/// The relay's single mutable connection: which target windiag it is currently pointed at, and the
/// live client to it.
/// </summary>
/// <remarks>
/// <para>The relay is one stdio MCP server registered once on the base machine, with no address of its
/// own. A <c>connect</c> call points it at a target windiag over HTTP; from then on it mirrors that
/// target's tools and forwards calls to it. Another <c>connect</c> repoints it. So a target's address
/// is runtime data carried in a tool call, never configuration — which is the whole point: the lab VMs
/// get a new IP every time, and neither the MCP registration nor Claude Code restarts to follow them.</para>
/// <para>State swaps are serialised: a <c>connect</c> or <c>disconnect</c> takes the lock, and a
/// forwarded call reads the current client under it, so a repoint mid-session cannot forward to a
/// half-torn-down client.</para>
/// </remarks>
internal sealed class RelayState : IAsyncDisposable
{
    private readonly ILoggerFactory _loggerFactory;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private McpClient? _client;
    private IReadOnlyList<Tool> _remoteTools = [];

    public RelayState(ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory;
    }

    public bool IsConnected => _client is not null;

    public string? Target { get; private set; }

    /// <summary>A snapshot of the target's tools, for the dynamic tools/list.</summary>
    public IReadOnlyList<Tool> RemoteTools => _remoteTools;

    /// <summary>Points the relay at a target windiag, replacing any current one.</summary>
    /// <returns>The number of tools the target exposes.</returns>
    public async Task<int> ConnectAsync(string address, string token, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

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
            Name = "windiag-relay",
            AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = $"Bearer {token}" }
        });

        McpClient client;
        try
        {
            client = await McpClient.CreateAsync(transport, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
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
            await client.DisposeAsync().ConfigureAwait(false);
            throw new RelayException(
                $"Connected to {address} but could not read its tool list: {ex.Message}", ex);
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await DisposeClientAsync().ConfigureAwait(false);
            _client = client;
            _remoteTools = tools;
            Target = address;
        }
        finally
        {
            _gate.Release();
        }

        return tools.Count;
    }

    /// <summary>Drops the current target, if any.</summary>
    public async Task DisconnectAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await DisposeClientAsync().ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Forwards one tool call to the current target and returns its result verbatim.</summary>
    public async Task<CallToolResult> ForwardAsync(
        string name,
        IReadOnlyDictionary<string, object?>? arguments,
        CancellationToken cancellationToken)
    {
        McpClient? client;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            client = _client;
        }
        finally
        {
            _gate.Release();
        }

        if (client is null)
        {
            throw new RelayException(
                "Not connected to a target. Call 'connect' with the target's windiag address and token " +
                "first, then retry.");
        }

        // The target's own tool does the real work and its result -- structured content, IsError and
        // all -- is passed straight back. The relay adds nothing to the payload; it only moves it.
        var args = arguments?.ToDictionary(pair => pair.Key, pair => pair.Value);

        try
        {
            return await client.CallToolAsync(name, args, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not RelayException)
        {
            throw new RelayException(
                $"The call to '{name}' on {Target} failed: {ex.Message}. If the target restarted (an " +
                "update_self, say), reconnect and retry.", ex);
        }
    }

    private async Task DisposeClientAsync()
    {
        if (_client is not null)
        {
            try { await _client.DisposeAsync().ConfigureAwait(false); } catch (Exception) { /* tearing down */ }
            _client = null;
            _remoteTools = [];
            Target = null;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await DisposeClientAsync().ConfigureAwait(false);
        _gate.Dispose();
    }

    /// <summary>Builds the JSON input-schema element for a control tool.</summary>
    internal static JsonElement Schema(string json) =>
        JsonSerializer.Deserialize<JsonElement>(json);
}

/// <summary>Raised for a relay-level failure: not connected, an unreachable target, a bad address.</summary>
internal sealed class RelayException : Exception
{
    public RelayException(string message) : base(message)
    {
    }

    public RelayException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
