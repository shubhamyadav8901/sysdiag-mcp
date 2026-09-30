using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Diag.Mcp.Server.Tests;

/// <summary>Tests that change the process's working directory, so they must never run beside others.</summary>
[CollectionDefinition(nameof(WorkingDirectoryCollection), DisableParallelization = true)]
public sealed class WorkingDirectoryCollection;

[Collection(nameof(WorkingDirectoryCollection))]
public sealed class HostContentRootTests
{
    [Fact]
    public async Task The_content_root_is_the_servers_own_directory_whatever_the_working_directory()
    {
        // systemd starts a service in /, and a content root of / stalled host startup before the server
        // printed a line: the unit sat in 'activating' until systemd killed it. The content root must not
        // depend on where the process happened to be started from.
        var original = Environment.CurrentDirectory;
        var elsewhere = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"diag-cwd-{Guid.NewGuid():N}")).FullName;
        try
        {
            Environment.CurrentDirectory = elsewhere;

            await using var app = DiagServerHost.BuildHttp(
                new HttpHostSettings("http://127.0.0.1:0", "t", "[test]", "TEST_TOKEN", "t"),
                builder =>
                {
                    builder.Logging.ClearProviders();
                    builder.Services.AddMcpServer().WithHttpTransport();
                });

            Assert.Equal(
                Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory),
                Path.TrimEndingDirectorySeparator(app.Environment.ContentRootPath));
        }
        finally
        {
            Environment.CurrentDirectory = original;
            Directory.Delete(elsewhere, recursive: true);
        }
    }
}
