using WinDiag.Mcp.Diagnostics.External;
using WinDiag.Mcp.Diagnostics.Locks;

namespace WinDiag.Mcp.Tests;

public sealed class DrainAsyncTests
{
    [Fact]
    public async Task Returns_the_output_when_the_stream_completes()
    {
        var completed = Task.FromResult("rows");

        Assert.Equal("rows", await ExternalToolRunner.DrainAsync(completed));
    }

    [Fact]
    public async Task Gives_up_instead_of_hanging_when_a_pipe_never_closes()
    {
        // A grandchild process that inherited the stdout handle keeps the pipe open even after the
        // child is killed, so ReadToEndAsync never completes. Before this bound existed, that hung the
        // MCP call forever -- past the timeout that was supposed to prevent exactly this.
        var neverCompletes = new TaskCompletionSource<string>();

        var drain = ExternalToolRunner.DrainAsync(neverCompletes.Task);
        var winner = await Task.WhenAny(drain, Task.Delay(TimeSpan.FromSeconds(30)));

        Assert.Same(drain, winner);
        Assert.Equal(string.Empty, await drain);
    }

    [Fact]
    public async Task Surfaces_a_stream_failure_rather_than_reporting_empty_output()
    {
        // A broken pipe must not masquerade as "the tool found nothing", which is what silently
        // swallowing the fault and returning string.Empty would look like to the caller.
        var faulted = Task.FromException<string>(new IOException("pipe broke"));

        await Assert.ThrowsAsync<IOException>(() => ExternalToolRunner.DrainAsync(faulted));
    }
}

public sealed class ToolLocatorTests
{
    [Fact]
    public void Reports_a_missing_tool_as_missing()
    {
        var locator = new ToolLocator();

        Assert.False(locator.TryResolve("windiag-definitely-not-installed.exe", out var path));
        Assert.Equal(string.Empty, path);
    }

    [Fact]
    public void Finds_a_tool_installed_after_an_earlier_lookup_failed()
    {
        // The real scenario: the operator installs Sysinternals while the server is already running.
        // If misses were cached, every later call would keep failing with an error telling them to do
        // the thing they just did, until someone restarted the server. Asserting two failed lookups
        // would NOT catch that -- it passes against the buggy version too -- so this test actually
        // creates the tool between the two calls.
        var locator = new ToolLocator();
        var name = $"windiag-late-install-{Guid.NewGuid():N}.exe";
        var directory = Directory.CreateTempSubdirectory("windiag-locator").FullName;
        var originalPath = Environment.GetEnvironmentVariable("PATH");

        try
        {
            Assert.False(locator.TryResolve(name, out _));

            File.WriteAllText(Path.Combine(directory, name), "not a real executable");
            Environment.SetEnvironmentVariable("PATH", directory + Path.PathSeparator + originalPath);

            Assert.True(locator.TryResolve(name, out var resolved));
            Assert.Equal(Path.Combine(directory, name), resolved);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PATH", originalPath);
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Reports_a_missing_tool_with_an_actionable_error()
    {
        var ex = Assert.Throws<ToolNotFoundException>(
            () => new ToolLocator().Resolve("windiag-definitely-not-installed.exe"));

        Assert.Equal("windiag-definitely-not-installed.exe", ex.ExecutableName);
        Assert.Contains("install it", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_a_blank_tool_name()
    {
        Assert.Throws<ArgumentException>(() => new ToolLocator().TryResolve("  ", out _));
    }
}

public sealed class PidReuseTests
{
    private static readonly DateTimeOffset Reported = new(2026, 8, 11, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Treats_a_matching_start_time_as_the_same_process()
    {
        Assert.False(RestartManagerLockInspector.IsPidReused(Reported, Reported));
    }

    [Fact]
    public void Tolerates_small_conversion_differences_in_the_start_time()
    {
        // FILETIME and Process.StartTime come from the same kernel value via different conversions, so
        // exact equality would produce spurious "PID was recycled" verdicts on real holders.
        Assert.False(RestartManagerLockInspector.IsPidReused(Reported, Reported.AddMilliseconds(900)));
        Assert.False(RestartManagerLockInspector.IsPidReused(Reported, Reported.AddSeconds(-1)));
    }

    [Fact]
    public void Treats_a_clearly_different_start_time_as_a_recycled_pid()
    {
        // The failure this prevents: naming an innocent process as the lock holder because the PID was
        // reused between the query and the lookup. Downstream, that PID could be handed to a kill.
        Assert.True(RestartManagerLockInspector.IsPidReused(Reported, Reported.AddSeconds(30)));
        Assert.True(RestartManagerLockInspector.IsPidReused(Reported, Reported.AddSeconds(-30)));
    }

    [Fact]
    public void Cannot_judge_reuse_without_a_reported_start_time()
    {
        // Restart Manager reported no start time, so there is nothing to compare. Assuming reuse would
        // discard a genuine holder; assuming freshness is the safer default and matches the rendering,
        // which never invites action on a holder it is unsure about.
        Assert.False(RestartManagerLockInspector.IsPidReused(null, Reported));
    }
}
