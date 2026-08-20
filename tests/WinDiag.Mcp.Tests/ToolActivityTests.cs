using WinDiag.Mcp.Hosting;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// Whether an update can tell that the server is busy.
/// </summary>
/// <remarks>
/// <para>This is the class that decides whether <c>update_self</c> cuts off work or waits for it. It
/// exists because a real update truncated a 90-second capture 34 seconds in, returned a transport
/// error instead of a result, and orphaned a 256 MB partial trace.</para>
/// <para>Everything here is deterministic. The one place a real timeout is used is the budget test,
/// where the whole point is that the budget expires; every other wait is released by an explicit
/// <c>End()</c>, never by a sleep, so a slow machine cannot turn a pass into a flake.</para>
/// </remarks>
public sealed class ToolActivityTests
{
    private static readonly TimeSpan Generous = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task Reports_idle_immediately_when_nothing_is_running()
    {
        // The ordinary deploy: one update_self against a target nobody else is using. If this waited
        // for anything, every quiet update would pay the full budget before restarting.
        var activity = new ToolActivity();
        activity.MarkUpdatePending();

        Assert.True(await activity.WaitForIdleAsync(Generous, CancellationToken.None));
    }

    [Fact]
    public async Task Waits_until_the_last_running_call_has_finished()
    {
        var activity = new ToolActivity();
        Assert.True(activity.TryBegin("system_overview", out _));
        Assert.True(activity.TryBegin("system_overview", out _));

        activity.MarkUpdatePending();
        var idle = activity.WaitForIdleAsync(Generous, CancellationToken.None);

        activity.End();

        // Still one call running: shutting down now is exactly the truncation this prevents.
        Assert.False(idle.IsCompleted);
        Assert.Equal(1, activity.InFlight);

        activity.End();

        Assert.True(await idle);
        Assert.Equal(0, activity.InFlight);
    }

    [Fact]
    public async Task Gives_up_after_the_budget_rather_than_stranding_the_server()
    {
        // A tool that never returns must not hold the update forever: the restart helper is already
        // spinning on this process id by the time anyone waits here.
        var activity = new ToolActivity();
        Assert.True(activity.TryBegin("system_overview", out _));
        activity.MarkUpdatePending();

        Assert.False(await activity.WaitForIdleAsync(TimeSpan.FromMilliseconds(50), CancellationToken.None));
    }

    [Fact]
    public async Task Stops_waiting_when_the_host_is_shutting_down_for_another_reason()
    {
        var activity = new ToolActivity();
        Assert.True(activity.TryBegin("system_overview", out _));
        activity.MarkUpdatePending();

        using var stopping = new CancellationTokenSource();
        var idle = activity.WaitForIdleAsync(Generous, stopping.Token);
        await stopping.CancelAsync();

        // Reported as "not drained" rather than thrown: the caller's next move is the same either way,
        // and an exception escaping the background task would skip the shutdown it must always reach.
        Assert.False(await idle);
    }

    [Fact]
    public void Refuses_a_new_call_once_an_update_is_pending()
    {
        var activity = new ToolActivity();
        activity.MarkUpdatePending();

        Assert.False(activity.TryBegin("system_overview", out var refusal));

        // The refusal is the only thing a caller sees mid-update, and it is also how a deploy script
        // knows the old process is still draining, so it has to say what to do rather than just "no".
        Assert.Contains("installing an update", refusal, StringComparison.Ordinal);
        Assert.Contains("retry", refusal, StringComparison.OrdinalIgnoreCase);

        // Refused calls must not be counted, or the drain waits on work that is not running.
        Assert.Equal(0, activity.InFlight);
    }

    [Fact]
    public void Still_admits_update_self_once_an_update_is_pending()
    {
        // The one exemption, and the reason force is a per-call choice rather than a first-call-only
        // one. Refusing update_self too would mean a caller who chose to wait could never change their
        // mind: a wedged call holding the drain for its whole budget would leave the console as the
        // only way out, which is exactly the trip this tool exists to remove.
        var activity = new ToolActivity();
        activity.MarkUpdatePending();

        Assert.False(activity.TryBegin("capture_activity", out _));
        Assert.True(activity.TryBegin(ToolActivity.EscalationTool, out var refusal));
        Assert.Null(refusal);

        // Exempt from the refusal, not from the count -- the drain still has to know it is running.
        Assert.Equal(1, activity.InFlight);
        activity.End();
    }

    [Fact]
    public void Admits_a_call_normally_when_no_update_is_pending()
    {
        var activity = new ToolActivity();

        Assert.True(activity.TryBegin("system_overview", out var refusal));
        Assert.Null(refusal);
        Assert.Equal(1, activity.InFlight);
    }

    [Fact]
    public async Task Counts_a_call_that_threw()
    {
        // End() belongs in a finally. If a throwing tool leaked its slot, the count would never reach
        // zero again and every later update would wait out its whole budget for nothing.
        var activity = new ToolActivity();

        Assert.True(activity.TryBegin("system_overview", out _));
        try
        {
            throw new InvalidOperationException("the tool failed");
        }
        catch (InvalidOperationException)
        {
            activity.End();
        }

        activity.MarkUpdatePending();
        Assert.True(await activity.WaitForIdleAsync(Generous, CancellationToken.None));
    }

    [Fact]
    public async Task Never_admits_a_call_it_has_not_counted()
    {
        // The race this class is built around: calls arriving at the same moment an update commits.
        // A call admitted but not counted would be shut down mid-flight without the update ever
        // knowing it existed. Hammered from several threads because the guarantee is a memory-ordering
        // one -- TryBegin and MarkUpdatePending each write, then read the other's flag, so at least one
        // of them sees the other.
        var activity = new ToolActivity();
        var admitted = 0;

        var callers = Enumerable.Range(0, 64).Select(index => Task.Run(() =>
        {
            if (activity.TryBegin("system_overview", out _))
            {
                Interlocked.Increment(ref admitted);
                activity.End();
            }
        })).ToArray();

        activity.MarkUpdatePending();
        await Task.WhenAll(callers);

        // Whatever the interleaving, every admitted call was also counted and released, so the server
        // reaches idle and the count balances exactly.
        Assert.True(await activity.WaitForIdleAsync(Generous, CancellationToken.None));
        Assert.Equal(0, activity.InFlight);
        Assert.InRange(admitted, 0, 64);
    }
}
