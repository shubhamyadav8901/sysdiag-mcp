using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// Drives the real built server over a real stdio transport.
/// </summary>
/// <remarks>
/// <para>This is the end-to-end check: it exercises the actual entrypoint, the actual DI wiring and
/// tool registration, and the actual transport, rather than a parallel in-process arrangement that
/// could drift from what ships.</para>
/// <para>It doubles as the stdout-purity guard. stdout is the JSON-RPC channel, so a single stray
/// <c>Console.WriteLine</c> or a misconfigured logger corrupts every session. Asserting that every
/// stdout line parses as JSON-RPC catches that the moment it is introduced.</para>
/// </remarks>
public sealed class StdioProtocolTests : IAsyncLifetime
{
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(30);

    private Process _server = null!;
    private readonly List<string> _stdoutLines = [];
    private readonly StringBuilder _stderr = new();

    public Task InitializeAsync()
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = ServerExecutable(out var dllArgument),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = new UTF8Encoding(false),
            StandardInputEncoding = new UTF8Encoding(false)
        };

        if (dllArgument is not null)
        {
            startInfo.ArgumentList.Add("exec");
            startInfo.ArgumentList.Add(dllArgument);
        }

        // Pin configuration so the test does not inherit whatever the developer has exported.
        startInfo.Environment["WINDIAG_READ_ONLY"] = "0";
        startInfo.Environment["WINDIAG_MAX_RESULTS"] = "50";

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
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        try
        {
            if (!_server.HasExited)
            {
                _server.StandardInput.Close();
                if (!_server.WaitForExit(5000))
                {
                    _server.Kill(entireProcessTree: true);
                }
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
    public async Task Initializes_lists_tools_and_answers_a_tool_call_over_stdio()
    {
        using var cts = new CancellationTokenSource(ReadTimeout);

        var initialize = await RoundTrip(
            """
            {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"windiag-tests","version":"1.0.0"}}}
            """,
            id: 1,
            cts.Token);

        Assert.True(initialize.TryGetProperty("result", out var initResult),
            $"initialize failed: {initialize}");
        Assert.True(initResult.TryGetProperty("serverInfo", out _));

        await Send("""{"jsonrpc":"2.0","method":"notifications/initialized"}""");

        var list = await RoundTrip("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""", id: 2, cts.Token);
        var toolNames = list.GetProperty("result").GetProperty("tools")
            .EnumerateArray()
            .Select(t => t.GetProperty("name").GetString())
            .ToArray();

        // Asserted as a complete set, not a subset: a tool that silently fails to register (a missing
        // DI entry, a bad attribute) would otherwise go unnoticed until someone tried to use it.
        string[] expected =
        [
            "autostart_audit", "capabilities", "capture_activity", "capture_dump", "effective_access",
            "event_log_tail", "file_signatures", "get_file", "named_pipes", "network_owners",
            "path_handle_search", "process_control", "process_handles", "process_list", "process_modules",
            "put_file", "query_activity", "registry_read", "service_config", "service_control",
            "system_overview", "who_locks_path"
        ];

        Assert.Equal(expected, toolNames.Order(StringComparer.Ordinal).ToArray());

        // Call the tool against a file this test holds open. Regardless of whether Restart Manager
        // attributes it, the call must succeed and produce the coverage-aware summary.
        var temp = Path.Combine(Path.GetTempPath(), $"windiag-stdio-{Guid.NewGuid():N}.tmp");
        await using (new FileStream(temp, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
        {
            // Concatenated rather than interpolated: the trailing brace run in this JSON collides with
            // raw-string interpolation delimiters.
            var request =
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"who_locks_path\""
                + ",\"arguments\":{\"path\":" + JsonSerializer.Serialize(temp) + "}}}";

            var call = await RoundTrip(request, id: 3, cts.Token);

            Assert.True(call.TryGetProperty("result", out var callResult), $"tools/call failed: {call}");
            Assert.False(
                callResult.TryGetProperty("isError", out var isError) && isError.GetBoolean(),
                $"tool reported an error: {callResult}");

            var structured = callResult.GetProperty("structuredContent");
            Assert.Equal(temp, structured.GetProperty("path").GetString());
            Assert.False(structured.GetProperty("exhaustive").GetBoolean());
        }

        File.Delete(temp);
    }

    /// <summary>
    /// A null-valued property still crosses the wire, through the real registration.
    /// </summary>
    /// <remarks>
    /// <para>The schema marks a constructor parameter without a default required, nullable or not, while
    /// the SDK's default serializer options omit nulls -- so a response whose nullable property is null
    /// is rejected by the client against the schema this server advertised. Seven tools were uncallable
    /// that way. <c>ServerBuilder.ToolJsonOptions</c> fixes it for every tool at the registration.</para>
    /// <para>This test exists because that fix is one argument on eighteen <c>WithTools</c> calls, and
    /// every other test of it serializes directly -- so dropping the argument, or adding a nineteenth
    /// registration without it, left the whole suite green while the defect came back. Here the assertion
    /// runs through the real entrypoint, the real registration and the real transport, which is the only
    /// place that gap is visible.</para>
    /// <para><c>file_signatures</c> against this server's own unsigned assembly is the deterministic
    /// case: an unsigned file has no signer, no issuer and no certificate expiry, so all three are null
    /// every time, on any machine, with no setup.</para>
    /// </remarks>
    [Fact]
    public async Task A_null_property_is_written_rather_than_omitted_over_the_real_transport()
    {
        using var cts = new CancellationTokenSource(ReadTimeout);

        await RoundTrip(
            """
            {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"windiag-tests","version":"1.0.0"}}}
            """,
            id: 1,
            cts.Token);

        await Send("""{"jsonrpc":"2.0","method":"notifications/initialized"}""");

        var unsigned = typeof(ServerBuilder).Assembly.Location;
        var request =
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"file_signatures\""
            + ",\"arguments\":{\"paths\":[" + JsonSerializer.Serialize(unsigned) + "]}}}";

        var call = await RoundTrip(request, id: 2, cts.Token);

        Assert.True(call.TryGetProperty("result", out var result), $"tools/call failed: {call}");
        var file = result.GetProperty("structuredContent").GetProperty("files")[0];

        // Present-and-null, not absent. Absent is what the schema rejects.
        foreach (var property in new[] { "signer", "issuer", "certificateNotAfter" })
        {
            Assert.True(
                file.TryGetProperty(property, out var value),
                $"'{property}' was omitted, so a client validating against this tool's own output schema "
                + $"rejects the response. Check ServerBuilder.ToolJsonOptions is passed to every "
                + $"WithTools registration. Got: {file}");

            Assert.Equal(JsonValueKind.Null, value.ValueKind);
        }
    }

    [Fact]
    public async Task Writes_diagnostics_to_stderr_and_keeps_stdout_pure_json_rpc()
    {
        using var cts = new CancellationTokenSource(ReadTimeout);

        await RoundTrip(
            """
            {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"windiag-tests","version":"1.0.0"}}}
            """,
            id: 1,
            cts.Token);

        // Drain anything the server emitted after its last reply. Checking only the lines consumed
        // while waiting for a response would miss a stray write that happens between requests, which
        // is exactly where a background logger would put one.
        await DrainRemainingStdout(TimeSpan.FromSeconds(2));

        Assert.NotEmpty(_stdoutLines);
        foreach (var line in _stdoutLines)
        {
            // The assertion that matters: nothing but protocol may appear here.
            var document = JsonDocument.Parse(line);
            Assert.Equal("2.0", document.RootElement.GetProperty("jsonrpc").GetString());
        }

        string stderr;
        lock (_stderr)
        {
            stderr = _stderr.ToString();
        }

        Assert.Contains("starting stdio server", stderr);
    }

    /// <summary>Collects any stdout the server emits within <paramref name="window"/>, then stops.</summary>
    private async Task DrainRemainingStdout(TimeSpan window)
    {
        using var cts = new CancellationTokenSource(window);

        try
        {
            while (await _server.StandardOutput.ReadLineAsync(cts.Token) is { } line)
            {
                if (!string.IsNullOrWhiteSpace(line))
                {
                    _stdoutLines.Add(line);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Expected: the server is idle and has nothing more to say.
        }
    }

    private async Task Send(string json)
    {
        await _server.StandardInput.WriteAsync(json + "\n");
        await _server.StandardInput.FlushAsync();
    }

    private async Task<JsonElement> RoundTrip(string request, int id, CancellationToken cancellationToken)
    {
        await Send(request);

        while (true)
        {
            var line = await _server.StandardOutput.ReadLineAsync(cancellationToken)
                       ?? throw new InvalidOperationException(
                           $"server closed stdout before replying to id {id}. stderr:\n{_stderr}");

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            _stdoutLines.Add(line);

            var document = JsonDocument.Parse(line);
            if (document.RootElement.TryGetProperty("id", out var idElement)
                && idElement.ValueKind == JsonValueKind.Number
                && idElement.GetInt32() == id)
            {
                return document.RootElement.Clone();
            }
        }
    }

    /// <summary>
    /// Finds the built server. Prefers the apphost so the test drives the artifact that ships;
    /// falls back to <c>dotnet exec</c> when only the managed assembly was copied.
    /// </summary>
    private static string ServerExecutable(out string? dllArgument)
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
            throw new FileNotFoundException(
                $"Neither WinDiag.Mcp.exe nor WinDiag.Mcp.dll was found in {AppContext.BaseDirectory}. " +
                "Run 'dotnet build' first.");
        }

        dllArgument = dll;
        return "dotnet";
    }
}
