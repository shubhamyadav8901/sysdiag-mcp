using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// Drives the real built server over its real HTTP transport.
/// </summary>
/// <remarks>
/// The counterpart to <see cref="StdioProtocolTests"/>, and the only check that the authentication
/// gate is actually wired into the pipeline. A correct <c>BearerTokenGate</c> that is never registered
/// as middleware would pass every unit test and leave the endpoint wide open.
/// </remarks>
public sealed class HttpProtocolTests : IAsyncLifetime
{
    private const string Token = "test-token-fedcba9876543210";

    private Process _server = null!;
    private HttpClient _client = null!;
    private string _address = null!;
    private readonly StringBuilder _stderr = new();
    private readonly StringBuilder _stdout = new();

    public async Task InitializeAsync()
    {
        _address = $"http://127.0.0.1:{FreePort()}";

        var startInfo = new ProcessStartInfo
        {
            FileName = ServerExecutable(out var dllArgument),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        if (dllArgument is not null)
        {
            startInfo.ArgumentList.Add("exec");
            startInfo.ArgumentList.Add(dllArgument);
        }

        startInfo.ArgumentList.Add("--http");
        startInfo.ArgumentList.Add(_address);

        // Pinned rather than generated so the test knows what to present.
        startInfo.Environment["WINDIAG_TOKEN"] = Token;
        startInfo.Environment["WINDIAG_READ_ONLY"] = "0";

        _server = new Process { StartInfo = startInfo };
        _server.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                lock (_stderr)
                {
                    _stderr.AppendLine(e.Data);
                }
            }
        };

        // Subscribed, not merely drained. BeginOutputReadLine without a handler discards stdout, which
        // would make any assertion about what does or does not appear there vacuous.
        _server.OutputDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                lock (_stdout)
                {
                    _stdout.AppendLine(e.Data);
                }
            }
        };

        _server.Start();
        _server.BeginErrorReadLine();
        _server.BeginOutputReadLine();

        _client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        await WaitUntilListening();
    }

    public Task DisposeAsync()
    {
        _client.Dispose();

        try
        {
            if (!_server.HasExited)
            {
                _server.Kill(entireProcessTree: true);
                _server.WaitForExit(5000);
            }
        }
        catch (InvalidOperationException)
        {
            // Already gone.
        }

        _server.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Rejects_a_request_with_no_token()
    {
        using var response = await Post(Initialize(1), token: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Bearer", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task Rejects_a_request_with_the_wrong_token()
    {
        using var response = await Post(Initialize(1), token: "not-the-token");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Rejects_a_token_that_is_a_prefix_of_the_real_one()
    {
        // Guards against a comparison that stops at the presented length.
        using var response = await Post(Initialize(1), token: Token[..10]);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Serves_a_full_mcp_session_to_an_authenticated_caller()
    {
        using var response = await Post(Initialize(1), Token);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadAsStringAsync();
        var payload = ExtractJson(body);

        Assert.True(payload.TryGetProperty("result", out var result), $"initialize failed: {body}");
        Assert.Equal("WinDiag.Mcp", result.GetProperty("serverInfo").GetProperty("name").GetString());

        var session = response.Headers.TryGetValues("Mcp-Session-Id", out var values)
            ? values.FirstOrDefault()
            : null;

        using (await Post("""{"jsonrpc":"2.0","method":"notifications/initialized"}""", Token, session))
        {
        }

        using var list = await Post("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""", Token, session);
        list.EnsureSuccessStatusCode();

        var tools = ExtractJson(await list.Content.ReadAsStringAsync())
            .GetProperty("result").GetProperty("tools")
            .EnumerateArray()
            .Select(t => t.GetProperty("name").GetString())
            .ToArray();

        // Same tool surface as stdio: the transport must not change what the server offers.
        Assert.Contains("system_overview", tools);
        Assert.Contains("who_locks_path", tools);
        Assert.Contains("capture_dump", tools);
        Assert.Contains("capture_activity", tools);
        Assert.Contains("process_control", tools);

        // update_self is deliberately absent: it is gated separately from read-only mode and the test
        // server does not enable it.
        Assert.DoesNotContain("update_self", tools);
        Assert.Equal(20, tools.Length);
    }

    [Fact]
    public async Task Announces_the_address_and_never_echoes_a_configured_token()
    {
        using (await Post(Initialize(1), Token))
        {
        }

        string stderr, stdout;
        lock (_stderr)
        {
            stderr = _stderr.ToString();
        }

        lock (_stdout)
        {
            stdout = _stdout.ToString();
        }

        Assert.Contains("serving MCP over HTTP", stderr);
        Assert.Contains(_address, stderr);

        // The token came from WINDIAG_TOKEN, so it is long-lived. Echoing it would put a standing
        // credential into whatever captures the server's output -- and running an elevated listener
        // under a service wrapper with `2> windiag.log` is the normal deployment, not an odd one.
        Assert.DoesNotContain(Token, stderr);
        Assert.DoesNotContain(Token, stdout);
        Assert.Contains("not logged", stderr);
    }

    // Concatenated rather than interpolated: the trailing brace run collides with raw-string
    // interpolation delimiters.
    private static string Initialize(int id) =>
        "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"method\":\"initialize\",\"params\":{"
        + "\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},"
        + "\"clientInfo\":{\"name\":\"windiag-tests\",\"version\":\"1.0.0\"}}}";

    private async Task<HttpResponseMessage> Post(string json, string? token, string? session = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, _address + "/")
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));

        if (token is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        if (session is not null)
        {
            request.Headers.Add("Mcp-Session-Id", session);
        }

        return await _client.SendAsync(request);
    }

    /// <summary>Pulls the JSON payload out of a response that may be a server-sent event stream.</summary>
    private static JsonElement ExtractJson(string body)
    {
        foreach (var line in body.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("data:", StringComparison.Ordinal))
            {
                return JsonDocument.Parse(trimmed["data:".Length..].Trim()).RootElement.Clone();
            }
        }

        return JsonDocument.Parse(body).RootElement.Clone();
    }

    private async Task WaitUntilListening()
    {
        for (var attempt = 0; attempt < 150; attempt++)
        {
            if (_server.HasExited)
            {
                throw new InvalidOperationException($"server exited during startup. stderr:\n{_stderr}");
            }

            try
            {
                // A 401 is a perfectly good readiness signal: it means the pipeline is up.
                using var response = await Post(Initialize(0), token: null);
                return;
            }
            catch (HttpRequestException)
            {
                await Task.Delay(100);
            }
        }

        throw new TimeoutException($"server never started listening on {_address}. stderr:\n{_stderr}");
    }

    internal static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    internal static string ServerExecutable(out string? dllArgument)
    {
        var exe = Path.Combine(AppContext.BaseDirectory, "WinDiag.Mcp.exe");
        if (File.Exists(exe))
        {
            dllArgument = null;
            return exe;
        }

        var dll = Path.Combine(AppContext.BaseDirectory, "WinDiag.Mcp.dll");
        if (!File.Exists(dll))
        {
            throw new FileNotFoundException($"the built server was not found in {AppContext.BaseDirectory}");
        }

        dllArgument = dll;
        return "dotnet";
    }
}
