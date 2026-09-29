using System.Security.Cryptography;
using Diag.Mcp.Server.Files;
using DiagRelay.Mcp;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Diag.Mcp.Server.Tests;

/// <summary>
/// The relay's real transfer code against the kit's real HTTP server, so neither side of the target
/// contract can drift without this going red. Until now the relay was only tested against a fake.
/// </summary>
public sealed class RelayContractTests : IAsyncLifetime
{
    private const string Token = "contract-test-token";

    private readonly string _root = Directory.CreateDirectory(
        Path.Combine(Path.GetTempPath(), $"diag-contract-{Guid.NewGuid():N}")).FullName;

    private WebApplication? _app;
    private McpClient? _client;

    public async Task InitializeAsync()
    {
        _app = DiagServerHost.BuildHttp(
            new HttpHostSettings("http://127.0.0.1:0", Token, "[test]", "TEST_TOKEN", Token),
            builder =>
            {
                builder.Logging.ClearProviders();
                builder.Services.AddSingleton(new FileTransferOptions(_root, false, false, "W=1", "R=1"));
                builder.Services.AddSingleton<IFileReceiver, FileReceiver>();
                builder.Services.AddSingleton<IFileSender, FileSender>();
                builder.Services.AddMcpServer()
                    .WithReadableToolErrors()
                    .WithTools<FileTools>(DiagServerKit.ToolJsonOptions)
                    .WithTools<FileReadTools>(DiagServerKit.ToolJsonOptions)
                    .WithHttpTransport();
            });
        await _app.StartAsync();

        _client = await McpClient.CreateAsync(Transport($"Bearer {Token}"));
    }

    public async Task DisposeAsync()
    {
        if (_client is not null)
        {
            await _client.DisposeAsync();
        }

        if (_app is not null)
        {
            await _app.DisposeAsync();
        }

        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    private HttpClientTransport Transport(string authorization) => new(new HttpClientTransportOptions
    {
        Endpoint = new Uri(_app!.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.First()),
        AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = authorization }
    });

    private async Task<CallToolResult> Forward(
        string tool, IReadOnlyDictionary<string, object?> arguments, CancellationToken cancellationToken) =>
        await _client!.CallToolAsync(tool, arguments, cancellationToken: cancellationToken);

    private string Local(string name) => Path.Combine(_root, name);

    [Theory]
    [InlineData(0)]                                   // zero-byte: refused by windiag before the kit
    [InlineData(10)]
    [InlineData(RelayFileTransfer.ChunkBytes + 7)]    // more than one chunk, and more than one slice
    public async Task A_file_pushed_by_the_relay_and_pulled_back_is_byte_identical(int size)
    {
        // Review Focus 5 rides on the zero row: an empty pull must end on its first slice, since the
        // relay treats an empty slice without endOfFile as a target that stopped answering.
        var content = new byte[size];
        Random.Shared.NextBytes(content);
        await File.WriteAllBytesAsync(Local("source.bin"), content);

        var pushed = await RelayFileTransfer.PushAsync(Forward, Local("source.bin"), Local("remote.bin"), true, CancellationToken.None);
        var pulled = await RelayFileTransfer.PullAsync(Forward, Local("remote.bin"), Local("back.bin"), true, CancellationToken.None);

        Assert.Equal(Convert.ToHexString(SHA256.HashData(content)), pushed.Sha256, ignoreCase: true);
        Assert.Equal(content, await File.ReadAllBytesAsync(Local("back.bin")));
        Assert.True(pulled.VerifiedAgainstTarget);
    }

    [Fact]
    public async Task The_kit_rejects_a_file_whose_assembled_hash_does_not_match_and_leaves_nothing()
    {
        byte[] bytes = [1, 2, 3];

        var result = await Forward("put_file", new Dictionary<string, object?>
        {
            ["path"] = Local("bad.bin"),
            ["contentBase64"] = Convert.ToBase64String(bytes),
            ["append"] = false,
            ["chunkSha256"] = Convert.ToHexString(SHA256.HashData(bytes)),
            ["expectedSha256"] = new string('0', 64)
        }, CancellationToken.None);

        Assert.True(result.IsError);
        Assert.False(File.Exists(Local("bad.bin")));
    }

    [Fact]
    public async Task A_bad_token_is_refused_at_the_http_layer()
    {
        await Assert.ThrowsAnyAsync<Exception>(async () => await McpClient.CreateAsync(Transport("Bearer wrong")));
    }
}
