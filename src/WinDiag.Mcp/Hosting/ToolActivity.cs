using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace WinDiag.Mcp.Hosting;

/// <summary>
/// Counts the tool calls running right now, so an update can wait for them instead of cutting them off.
/// </summary>
/// <remarks>
/// <para><c>update_self</c> used to replace the binary while the server was mid-answer. Measured on a
/// target: a 90-second <c>capture_activity</c> was truncated 34 seconds in, the caller got a raw
/// transport error rather than a result, and a 256 MB partial trace was left behind with nothing to
/// collect it. The 34 seconds were not a decision -- they were the .NET host's default shutdown
/// timeout, which nothing had ever set.</para>
/// <para>So the server now knows what it is doing. The call-tool filter reports every call here, and
/// <c>update_self</c> waits for the count to reach zero before it lets the process stop.</para>
/// <para>All of the logic lives in this class rather than in the filter closure, because there is no
/// in-memory MCP transport in this project -- the protocol tests spawn a real process -- so anything
/// written inside the closure cannot be unit tested at all. <c>BearerTokenGate.IsAuthorized</c> is the
/// same shape for the same reason.</para>
/// </remarks>
public sealed class ToolActivity
{
    private int _inFlight;

    /// <summary>0 or 1. An int rather than a bool so it can be read and written with <see cref="Interlocked"/>.</summary>
    private int _pending;

    private readonly TaskCompletionSource _idle = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>How many tool calls are executing right now.</summary>
    public int InFlight => Interlocked.CompareExchange(ref _inFlight, 0, 0);

    /// <summary>True once an update has been committed and the server is on its way down.</summary>
    public bool IsUpdatePending => Interlocked.CompareExchange(ref _pending, 0, 0) == 1;

    /// <summary>
    /// Admits a call and counts it, or refuses it because the server is shutting down to update.
    /// </summary>
    /// <param name="refusal">What to tell the caller, set only when the call is refused.</param>
    /// <remarks>
    /// The check-increment-check is deliberate and is the correctness core of the whole feature. A
    /// single check before the increment would let a call slip in after <see cref="MarkUpdatePending"/>
    /// had already read the count as zero -- the update would then stop the process out from under a
    /// call it never knew about, which is the exact bug this class exists to prevent. Because both this
    /// method and <see cref="MarkUpdatePending"/> write with <see cref="Interlocked"/>, and each reads
    /// the other's flag after its own write, at least one of them must observe the other. A call can
    /// therefore never be both admitted and uncounted.
    /// </remarks>
    public bool TryBegin([NotNullWhen(false)] out string? refusal)
    {
        if (IsUpdatePending)
        {
            refusal = Refusal();
            return false;
        }

        Interlocked.Increment(ref _inFlight);

        if (IsUpdatePending)
        {
            // Lost the race: an update was committed between the check above and the increment. Give
            // the slot back -- and through End(), so that if this was the last straggler the waiting
            // update is still released rather than sitting until its timeout.
            End();
            refusal = Refusal();
            return false;
        }

        refusal = null;
        return true;
    }

    /// <summary>Reports a call as finished. Must be called from a <c>finally</c>, including when the tool threw.</summary>
    public void End()
    {
        if (Interlocked.Decrement(ref _inFlight) == 0 && IsUpdatePending)
        {
            _idle.TrySetResult();
        }
    }

    /// <summary>
    /// Refuses every call from now on, so the server is guaranteed to reach idle.
    /// </summary>
    /// <remarks>
    /// Without this a target under steady load never quiesces: something new always arrives before the
    /// last call finishes, the drain waits out its whole budget, and the update truncates work anyway
    /// having achieved nothing but delay. Call it only once the update is committed -- marking it and
    /// then refusing the update would leave the server rejecting everything for no reason.
    /// </remarks>
    public void MarkUpdatePending()
    {
        Interlocked.Exchange(ref _pending, 1);

        // The common case by far: a deploy against an otherwise idle target. Nothing will call End(),
        // so release the waiter here or it would wait for the full timeout on every quiet update.
        if (InFlight == 0)
        {
            _idle.TrySetResult();
        }
    }

    /// <summary>
    /// Waits until no tool call is running, or until the budget runs out.
    /// </summary>
    /// <returns>True if the server reached idle; false if the budget expired with calls still running.</returns>
    /// <remarks>
    /// A false return is not a reason to abandon the update. By the time anyone waits here the restart
    /// helper is already launched and spinning on this process id, so a server that decided not to exit
    /// would leave that helper waiting forever and the staged build unused. The budget exists only so a
    /// tool that never returns cannot strand the update indefinitely.
    /// </remarks>
    public async Task<bool> WaitForIdleAsync(TimeSpan bound, CancellationToken cancellationToken)
    {
        try
        {
            await _idle.Task.WaitAsync(bound, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (TimeoutException)
        {
            return false;
        }
        catch (OperationCanceledException)
        {
            // The host is stopping for some other reason. Stop waiting and let shutdown proceed.
            return false;
        }
    }

    /// <summary>
    /// What a caller sees when it arrives mid-update.
    /// </summary>
    /// <remarks>
    /// This refusal is also the signal that tells a caller when to reconnect: it is returned by the OLD
    /// process, so the moment calls stop being refused, the new one is up. tools/deploy-target.ps1
    /// relies on exactly that, which is why nothing is exempt from the gate.
    /// </remarks>
    private string Refusal() =>
        "This server is installing an update and is not accepting new calls. It is waiting for "
        + InFlight.ToString(CultureInfo.InvariantCulture)
        + " call(s) already running to finish, then it restarts on the same address. Nothing you sent "
        + "has been lost - retry when calls stop being refused, which is how you know the new build is up.";
}
