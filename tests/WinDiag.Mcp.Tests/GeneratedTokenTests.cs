using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// Covers the path where no token is configured and the server generates one.
/// </summary>
/// <remarks>
/// Worth its own fixture because it is the branch an operator hits first — they run the exe, read the
/// token off the console, and paste it into a config. If that branch ever produced no token, or
/// produced one the gate did not accept, the endpoint would either be unusable or unauthenticated,
/// and every other HTTP test pins <c>WINDIAG_TOKEN</c> and so would miss it.
/// </remarks>
public sealed partial class GeneratedTokenTests : IAsyncLifetime
{
    private Process _server = null!;
    private HttpClient _client = null!;
    private string _address = null!;
    private readonly StringBuilder _stderr = new();

    public async Task InitializeAsync()
    {
        _address = $"http://127.0.0.1:{HttpProtocolTests.FreePort()}";

        var startInfo = new ProcessStartInfo
        {
            FileName = HttpProtocolTests.ServerExecutable(out var dllArgument),
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

        // Deliberately absent, and cleared in case the developer has it exported.
        startInfo.Environment.Remove("WINDIAG_TOKEN");

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

        _server.Start();
        _server.BeginErrorReadLine();
        _server.BeginOutputReadLine();

        _client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        await WaitForToken();
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
    public void Prints_a_generated_token_and_says_it_is_not_durable()
    {
        var stderr = Stderr();

        Assert.Contains("generated bearer token:", stderr);
        Assert.Contains("changes on restart", stderr);
        Assert.Matches(TokenPattern(), stderr);
    }

    [Fact]
    public async Task The_generated_token_is_the_one_the_gate_accepts()
    {
        var token = ReadToken() ?? throw new InvalidOperationException($"no token in stderr:\n{Stderr()}");

        using var accepted = await Post(token);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);

        using var rejected = await Post(token: null);
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
    }

    private async Task<HttpResponseMessage> Post(string? token)
    {
        const string body =
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}""";

        using var request = new HttpRequestMessage(HttpMethod.Post, _address + "/")
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };

        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));

        if (token is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return await _client.SendAsync(request);
    }

    private string Stderr()
    {
        lock (_stderr)
        {
            return _stderr.ToString();
        }
    }

    private string? ReadToken()
    {
        var match = TokenPattern().Match(Stderr());
        return match.Success ? match.Groups[1].Value : null;
    }

    private async Task WaitForToken()
    {
        for (var attempt = 0; attempt < 150; attempt++)
        {
            if (_server.HasExited)
            {
                throw new InvalidOperationException($"server exited during startup. stderr:\n{Stderr()}");
            }

            if (ReadToken() is not null)
            {
                // The banner is written before the listener is bound, so still wait for the port.
                try
                {
                    using var probe = await Post(token: null);
                    return;
                }
                catch (HttpRequestException)
                {
                    // Not listening yet.
                }
            }

            await Task.Delay(100);
        }

        throw new TimeoutException($"server never announced a token. stderr:\n{Stderr()}");
    }

    [GeneratedRegex(@"generated bearer token: ([0-9a-f]{64})")]
    private static partial Regex TokenPattern();
}
