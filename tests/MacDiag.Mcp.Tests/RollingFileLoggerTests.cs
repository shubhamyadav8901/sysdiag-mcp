using System.Runtime.Versioning;
using MacDiag.Mcp.Hosting;
using Microsoft.Extensions.Logging;

namespace MacDiag.Mcp.Tests;

// The sink creates its file owner-only, which .NET supports only on Unix; it runs only under launchd.
[UnsupportedOSPlatform("windows")]
public sealed class RollingFileLoggerTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("roll-").FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [UnixFact]
    public void Lines_are_written_and_the_file_rolls_to_one_backup_past_its_limit()
    {
        var path = Path.Combine(_root, "macdiag.log");
        using var provider = new RollingFileLoggerProvider(path, maxBytes: 200);
        var logger = provider.CreateLogger("macdiag");

        for (var i = 0; i < 20; i++)
        {
            logger.LogInformation("line {Number} with some padding to fill the file", i);
        }

        Assert.True(File.Exists(path + ".1"));
        Assert.Contains("line 19", File.ReadAllText(path), StringComparison.Ordinal);
        Assert.True(new FileInfo(path).Length <= 400);
    }

    [UnixFact]
    public void A_log_that_cannot_be_written_never_throws_into_the_server()
    {
        // A diagnostic channel must never break the thing it reports on: a sink that threw took down update_self.
        var blocked = Path.Combine(_root, "file-not-dir");
        File.WriteAllText(blocked, "");
        using var provider = new RollingFileLoggerProvider(Path.Combine(blocked, "macdiag.log"), maxBytes: 200);

        provider.CreateLogger("macdiag").LogError(new InvalidOperationException("boom"), "still fine");
    }
}
