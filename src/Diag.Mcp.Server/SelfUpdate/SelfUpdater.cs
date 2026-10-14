using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Diag.Mcp.Server.SelfUpdate;

/// <summary>
/// Installs a staged build by handing the swap to a detached helper and then exiting.
/// </summary>
/// <remarks>
/// <para>The engine is shared: the file-name-only rule, the hash, the commit-once claim and the drain are
/// the same on every platform. How a build is inspected, what else it must satisfy and how the process
/// is brought back are each server's (<see cref="IStagedBuildInspector"/>, <see cref="IUpdateGuard"/>,
/// <see cref="IRestartHelper"/>).</para>
/// <para>Exists because file copy is the only channel some targets offer. On a lab VM reachable by SMB
/// but not by WinRM or DCOM, a new binary can be delivered but nothing can stop the process holding the
/// old one open — so every update needed someone at the console.</para>
/// <para><strong>This is the most dangerous code in the project.</strong> It replaces an executable that
/// runs elevated and starts it again, so a caller holding the bearer token could otherwise run anything
/// as SYSTEM. Three things constrain it: the tool is not registered unless explicitly enabled, the
/// caller must state the exact hash they expect, and each server's <see cref="IUpdateGuard"/> -- which
/// differs by platform. On Windows a signed server accepts only a valid signature from its own
/// publisher; MacDiag requires a Mach-O the Mac can run and, for arm64, a signature codesign verifies,
/// ad hoc included; LinuxDiag requires an x86-64 ELF and checks no signature at all.</para>
/// </remarks>
public sealed class SelfUpdater : ISelfUpdater
{
    private readonly IStagedBuildInspector _inspector;
    private readonly IUpdateGuard _guard;
    private readonly IRestartHelper _helper;
    private readonly SelfUpdateOptions _options;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ToolActivity _activity;
    private readonly ILogger<SelfUpdater> _logger;

    /// <summary>
    /// Grace period before shutting down, so the caller receives its reply first.
    /// </summary>
    /// <remarks>
    /// Still needed after the drain, and for a reason worth stating: the activity count reaching zero
    /// means every tool BODY has returned, not that any reply has been serialized and flushed to the
    /// transport. This covers that last step -- including this call's own reply. Deleting it because
    /// "the drain already waited" would put every update back to racing its own answer.
    /// </remarks>
    private static readonly TimeSpan ReplyGrace = TimeSpan.FromSeconds(3);

    /// <summary>The executable being replaced. The running process's own, except under test.</summary>
    /// <remarks>
    /// Init-only and internal: nothing a caller or a setting can reach. It exists so the engine's tests
    /// can stage a build in their own directory rather than beside the test host -- which on a CI runner
    /// may not be writable, and which one earlier test did overwrite with junk.
    /// </remarks>
    internal Func<string?> LivePath { get; init; } = static () => Environment.ProcessPath;

    /// <summary>0 or 1. Set once an update is past every check and the helper is about to be launched.</summary>
    private int _committed;

    /// <summary>Trips the drain early when a later call escalates to force.</summary>
    private readonly CancellationTokenSource _drainCancelled = new();

    public SelfUpdater(
        IStagedBuildInspector inspector,
        IUpdateGuard guard,
        IRestartHelper helper,
        SelfUpdateOptions options,
        IHostApplicationLifetime lifetime,
        ToolActivity activity,
        ILogger<SelfUpdater> logger)
    {
        _inspector = inspector;
        _guard = guard;
        _helper = helper;
        _options = options;
        _lifetime = lifetime;
        _activity = activity;
        _logger = logger;
    }

    /// <summary>
    /// Puts a caller-supplied hash into the one shape the comparison uses.
    /// </summary>
    /// <remarks>
    /// Hashes get copied out of certutil, PowerShell and this server's own output in several shapes.
    /// Rejecting on formatting alone would only train callers to paste less carefully, so separators and
    /// surrounding whitespace are stripped and the comparison itself is case-insensitive. Exposed so
    /// this can be tested without calling <see cref="Update"/>, which past the hash check goes on to
    /// launch a real helper against whatever executable is running -- in a test run, the test host.
    /// </remarks>
    internal static string NormalizeHash(string expectedSha256) =>
        expectedSha256.Trim().Replace("-", string.Empty);

    public SelfUpdateResult Update(
        string expectedSha256, string stagedFileName, bool force, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedSha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(stagedFileName);
        cancellationToken.ThrowIfCancellationRequested();

        var live = LivePath()
                   ?? throw new SelfUpdateRejectedException("Cannot determine this server's own executable path.");

        var directory = Path.GetDirectoryName(live)!;

        // A file name, never a path: a caller must not be able to point this at an arbitrary location.
        if (Path.GetFileName(stagedFileName) != stagedFileName)
        {
            throw new SelfUpdateRejectedException(
                $"'{stagedFileName}' must be a file name, not a path. The staged build is only ever read " +
                "from the directory the server runs in.");
        }

        var staged = Path.Combine(directory, stagedFileName);
        if (!File.Exists(staged))
        {
            throw new SelfUpdateRejectedException(
                $"No staged build at '{staged}'. Copy the new executable there first.");
        }

        var inspection = _inspector.Inspect(staged, cancellationToken);

        var expected = NormalizeHash(expectedSha256);
        if (!string.Equals(inspection.Sha256, expected, StringComparison.OrdinalIgnoreCase))
        {
            // The check that matters most. A transfer to a target reached exactly the right size and was
            // corrupt, twice; only the hash caught it.
            throw new SelfUpdateRejectedException(
                $"The staged build does not match the hash you gave. Expected {expected}, found " +
                $"{inspection.Sha256}. Nothing has been changed. Re-send the file and try again.");
        }

        _guard.RequireAcceptable(live, inspection, cancellationToken);

        var log = Path.Combine(_options.ArtifactDirectory, "self-update.log");

        // Claimed here and nowhere earlier: after every check, so a refused update never costs the
        // server anything, and before the helper is launched, so two callers arriving together cannot
        // both write self-update.cmd and leave two helpers spinning on the same process id.
        if (Interlocked.Exchange(ref _committed, 1) == 1)
        {
            if (!force)
            {
                throw new SelfUpdateRejectedException(
                    "An update has already been accepted on this server and it is waiting for running "
                    + "calls to finish before it restarts. Nothing has been changed by this call. Call "
                    + "update_self again with force to stop waiting and restart now, or reconnect once "
                    + "calls stop being refused.");
            }

            // Escalation: the helper is already launched and the drain is running, so there is nothing
            // to install again -- only a decision to stop waiting. This is the whole reason update_self
            // is exempt from the gate; without it, choosing to wait was irreversible.
            _drainCancelled.Cancel();
            _logger.LogWarning("drain cancelled by a forced update; restarting without waiting");

            return new SelfUpdateResult(
                StagedPath: staged,
                LivePath: live,
                SizeBytes: inspection.SizeBytes,
                Sha256: inspection.Sha256,
                SignatureVerdict: inspection.SignatureVerdict,
                HelperLogPath: log,
                RestartScheduled: true,
                Forced: true,
                OtherCallsInFlight: Math.Max(0, _activity.InFlight - 1),
                DrainTimeoutSeconds: 0);
        }

        try
        {
            Directory.CreateDirectory(_options.ArtifactDirectory);
            _helper.Launch(live, staged, inspection.Sha256, log);
        }
        catch (Exception ex)
        {
            // Nothing was launched, so nothing is shutting down -- give the claim back. Leaving it set
            // would be far worse than the failure itself: every later update would be told one is
            // already in progress, which would be a lie, and the only way out of it would be the trip
            // to the console this whole tool exists to avoid.
            Interlocked.Exchange(ref _committed, 0);

            if (ex is SelfUpdateRejectedException)
            {
                throw;
            }

            // Anything else surfaces as "An error occurred invoking 'update_self'." -- the exact
            // unreadable refusal this project added error translation to prevent, and it landed on the
            // most dangerous tool here. Naming the type costs nothing and is the difference between a
            // diagnosable failure and guesswork, which is what the first one cost.
            throw new SelfUpdateRejectedException(
                $"The update could not be started: {ex.GetType().Name}: {ex.Message} Nothing has been "
                + "changed and this server is still running the build it was.");
        }

        // Before the reply goes out, and that ordering is the contract. The refusal callers get is what
        // tells them the old process is still draining -- deploy-target.ps1 treats a real answer as
        // proof the NEW build is up. Marking this after the reply had been dispatched would leave a
        // window where the caller's next request is answered normally by a server that is on its way
        // down. It is still only reached past every rejection, which is what matters for not turning a
        // refused update into a server that stops accepting calls.
        _activity.MarkUpdatePending();

        // This call is itself counted by the tool-activity gate, so discount it to report what the
        // server is actually waiting for.
        var others = Math.Max(0, _activity.InFlight - 1);

        _logger.LogWarning(
            "self-update accepted ({Sha}); handing over to the helper and shutting down", inspection.Sha256);

        // Reply first, exit second: the caller needs the response before the socket dies, and the file
        // stays locked until this process is gone.
        //
        // The whole wait lives in here, off the request path, and that placement is load-bearing. This
        // call occupies a slot in the activity count until Update returns, so awaiting the drain from
        // the request thread would wait for a count that includes itself -- it could never reach zero,
        // and every update would stall for the full timeout. That failure looks like a slow network,
        // not a deadlock, which is why it is worth a comment and a test rather than a note.
        _ = Task.Run(async () =>
        {
            try
            {
                if (!force)
                {
                    // Two ways out besides finishing: the host stopping for its own reasons, and a later
                    // caller escalating to force. Both mean stop waiting, so both are just cancellation.
                    using var stop = CancellationTokenSource.CreateLinkedTokenSource(
                        _lifetime.ApplicationStopping, _drainCancelled.Token);

                    var drained = await _activity
                        .WaitForIdleAsync(_options.DrainTimeout, stop.Token)
                        .ConfigureAwait(false);

                    if (!drained)
                    {
                        _logger.LogWarning(
                            "update drain ended early or timed out after up to {Seconds:0}s with "
                            + "{InFlight} call(s) still running; restarting anyway and cutting them off",
                            _options.DrainTimeout.TotalSeconds,
                            _activity.InFlight);
                    }
                }

                await Task.Delay(ReplyGrace).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "the update drain failed; shutting down anyway");
            }
            finally
            {
                // Must always run. The helper is already launched and sitting in a loop waiting for this
                // process id to disappear, so a server that decided not to exit would leave it spinning
                // forever and the staged build never installed.
                try
                {
                    _lifetime.StopApplication();
                }
                catch (Exception ex)
                {
                    // Nothing above can recover from this and the task has no observer, so without a log
                    // line the symptom is a server that simply never restarts and a helper burning a
                    // core against a process id that will not go away.
                    _logger.LogCritical(ex, "could not stop the host after an accepted update");
                }
            }
        });

        return new SelfUpdateResult(
            StagedPath: staged,
            LivePath: live,
            SizeBytes: inspection.SizeBytes,
            Sha256: inspection.Sha256,
            SignatureVerdict: inspection.SignatureVerdict,
            HelperLogPath: log,
            RestartScheduled: true,
            Forced: force,
            OtherCallsInFlight: others,
            DrainTimeoutSeconds: force ? 0 : (int)_options.DrainTimeout.TotalSeconds);
    }
}
