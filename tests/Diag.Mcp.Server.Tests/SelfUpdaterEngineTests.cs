using Diag.Mcp.Server.SelfUpdate;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;

namespace Diag.Mcp.Server.Tests;

/// <summary>The shared update engine: every check happens before anything irreversible does.</summary>
public sealed class SelfUpdaterEngineTests : IDisposable
{
    private readonly string _directory = Directory.CreateDirectory(
        Path.Combine(Path.GetTempPath(), $"diag-update-{Guid.NewGuid():N}")).FullName;

    public void Dispose()
    {
        try { Directory.Delete(_directory, recursive: true); } catch (IOException) { }
    }

    private sealed class Inspector(string sha) : IStagedBuildInspector
    {
        public StagedBuild Inspect(string path, CancellationToken cancellationToken) =>
            new(sha, 3, "Unsigned", null);
    }

    private sealed class AnyGuard : IUpdateGuard
    {
        public void RequireAcceptable(string livePath, StagedBuild staged, CancellationToken cancellationToken)
        {
        }
    }

    private sealed class RecordingHelper : IRestartHelper
    {
        public int Launches { get; private set; }

        public void Launch(string livePath, string stagedPath, string sha256, string logPath) => Launches++;
    }

    private sealed class Lifetime : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => CancellationToken.None;

        public CancellationToken ApplicationStopping => CancellationToken.None;

        public CancellationToken ApplicationStopped => CancellationToken.None;

        public void StopApplication() => throw new InvalidOperationException("a refusal must never stop the host");
    }

    [Fact]
    public void A_hash_mismatch_is_refused_before_the_restart_helper_is_ever_launched()
    {
        // The order is the safety property: a helper launched ahead of the hash check would swap in a
        // build nobody vouched for. The helper here only counts, so a regression cannot touch anything.
        File.WriteAllBytes(Path.Combine(_directory, "staged.bin"), [1, 2, 3]);
        var helper = new RecordingHelper();
        var activity = new ToolActivity();
        var updater = new SelfUpdater(
            new Inspector("AAAA"), new AnyGuard(), helper,
            new SelfUpdateOptions(_directory, TimeSpan.FromSeconds(1)),
            new Lifetime(), activity, NullLogger<SelfUpdater>.Instance)
        {
            LivePath = () => Path.Combine(_directory, "live.bin")
        };

        var ex = Assert.Throws<SelfUpdateRejectedException>(
            () => updater.Update("BBBB", "staged.bin", force: false, CancellationToken.None));

        Assert.Contains("does not match the hash you gave", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, helper.Launches);
        Assert.False(activity.IsUpdatePending);
    }
}
