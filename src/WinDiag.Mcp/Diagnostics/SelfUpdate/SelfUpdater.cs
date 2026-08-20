using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.Signatures;
using WinDiag.Mcp.Hosting;

namespace WinDiag.Mcp.Diagnostics.SelfUpdate;

/// <summary>
/// Installs a staged build by handing the swap to a detached helper and then exiting.
/// </summary>
/// <remarks>
/// <para>Exists because file copy is the only channel some targets offer. On a lab VM reachable by SMB
/// but not by WinRM or DCOM, a new binary can be delivered but nothing can stop the process holding the
/// old one open — so every update needed someone at the console.</para>
/// <para><strong>This is the most dangerous code in the project.</strong> It replaces an executable that
/// runs elevated and starts it again, so a caller holding the bearer token could otherwise run anything
/// as SYSTEM. Three things constrain it: the tool is not registered unless explicitly enabled, the
/// caller must state the exact hash they expect, and a signed server will only accept a validly signed
/// replacement.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class SelfUpdater : ISelfUpdater
{
    private readonly ISignatureInspector _signatures;
    private readonly WinDiagOptions _options;
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

    /// <summary>0 or 1. Set once an update is past every check and the helper is about to be launched.</summary>
    private int _committed;

    public SelfUpdater(
        ISignatureInspector signatures,
        WinDiagOptions options,
        IHostApplicationLifetime lifetime,
        ToolActivity activity,
        ILogger<SelfUpdater> logger)
    {
        _signatures = signatures;
        _options = options;
        _lifetime = lifetime;
        _activity = activity;
        _logger = logger;
    }

    public SelfUpdateResult Update(
        string expectedSha256, string stagedFileName, bool force, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedSha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(stagedFileName);
        cancellationToken.ThrowIfCancellationRequested();

        var live = Environment.ProcessPath
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

        var inspection = _signatures.Inspect([staged], cancellationToken).Files.Single();

        var expected = expectedSha256.Trim().Replace("-", string.Empty);
        if (!string.Equals(inspection.Sha256, expected, StringComparison.OrdinalIgnoreCase))
        {
            // The check that matters most. A transfer to a target reached exactly the right size and was
            // corrupt, twice; only the hash caught it.
            throw new SelfUpdateRejectedException(
                $"The staged build does not match the hash you gave. Expected {expected}, found " +
                $"{inspection.Sha256}. Nothing has been changed. Re-send the file and try again.");
        }

        RequireSignatureRatchet(live, inspection, cancellationToken);

        // Claimed here and nowhere earlier: after every check, so a refused update never costs the
        // server anything, and before the helper is launched, so two callers arriving together cannot
        // both write self-update.cmd and leave two helpers spinning on the same process id.
        if (Interlocked.Exchange(ref _committed, 1) == 1)
        {
            throw new SelfUpdateRejectedException(
                "An update has already been accepted on this server and it is shutting down to install "
                + "it. Nothing has been changed by this call. Reconnect once calls stop being refused, "
                + "then check the version.");
        }

        var log = Path.Combine(_options.ArtifactDirectory, "self-update.log");
        Directory.CreateDirectory(_options.ArtifactDirectory);

        LaunchHelper(live, staged, inspection.Sha256, log);

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
                // Only now, past every rejection: marking it earlier would leave a server that REFUSED
                // an update turning away callers until the timeout expired.
                _activity.MarkUpdatePending();

                if (!force)
                {
                    var drained = await _activity
                        .WaitForIdleAsync(_options.UpdateDrainTimeout, _lifetime.ApplicationStopping)
                        .ConfigureAwait(false);

                    if (!drained)
                    {
                        _logger.LogWarning(
                            "update drain gave up after {Seconds:0}s with {InFlight} call(s) still "
                            + "running; restarting anyway and cutting them off",
                            _options.UpdateDrainTimeout.TotalSeconds,
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
                _lifetime.StopApplication();
            }
        });

        return new SelfUpdateResult(
            StagedPath: staged,
            LivePath: live,
            SizeBytes: inspection.SizeBytes,
            Sha256: inspection.Sha256,
            SignatureVerdict: inspection.Verdict.ToString(),
            HelperLogPath: log,
            RestartScheduled: true,
            Forced: force,
            OtherCallsInFlight: others,
            DrainTimeoutSeconds: force ? 0 : (int)_options.UpdateDrainTimeout.TotalSeconds);
    }

    /// <summary>
    /// A signed server refuses an unsigned or untrusted replacement.
    /// </summary>
    /// <remarks>
    /// Deliberately a ratchet rather than a setting. Unsigned development builds keep working, but once
    /// a target runs a signed build it cannot be downgraded to an unsigned one through this path — which
    /// is exactly the move an attacker with the token would want.
    /// </remarks>
    private void RequireSignatureRatchet(string live, FileSignature staged, CancellationToken cancellationToken)
    {
        var current = _signatures.Inspect([live], cancellationToken).Files.Single();

        if (current.Verdict != SignatureVerdict.Valid)
        {
            _logger.LogWarning(
                "the running build is unsigned, so the replacement's signature ({Verdict}) is not enforced",
                staged.Verdict);
            return;
        }

        if (staged.Verdict != SignatureVerdict.Valid)
        {
            throw new SelfUpdateRejectedException(
                $"This server is running a signed build, so it will only accept a signed replacement. " +
                $"The staged file is {staged.Verdict}: {staged.Detail} Nothing has been changed.");
        }
    }

    /// <summary>Writes and starts the helper that performs the swap once this process has exited.</summary>
    /// <remarks>
    /// The helper inherits this process's environment, so the relaunched server keeps its token without
    /// it ever being written to disk. It re-verifies the hash before moving, because the window between
    /// this check and the swap is one an attacker with file access could otherwise use.
    /// </remarks>
    private void LaunchHelper(string live, string staged, string sha256, string log)
    {
        var helper = Path.Combine(_options.ArtifactDirectory, "self-update.cmd");
        var arguments = string.Join(' ', Environment.GetCommandLineArgs().Skip(1).Select(Quote));

        var script = new StringBuilder()
            .AppendLine("@echo off")
            .AppendLine("setlocal enabledelayedexpansion")
            .AppendLine($">\"{log}\" echo [%date% %time%] self-update starting for PID {Environment.ProcessId}")
            .AppendLine(":waitforexit")
            .AppendLine($"tasklist /FI \"PID eq {Environment.ProcessId}\" 2>nul | find \"{Environment.ProcessId}\" >nul")
            // ping, not timeout: timeout.exe needs a console and this helper is started with
            // CreateNoWindow, so where it has none it fails instantly and the loop becomes a hot spin.
            // That was invisible while the wait was only ever a few seconds; with a drain the loop can
            // now run for minutes, which would be a pegged core and a tasklist storm.
            .AppendLine("if not errorlevel 1 (ping -n 2 127.0.0.1 >nul & goto waitforexit)")
            .AppendLine($">>\"{log}\" echo [%time%] server exited; re-verifying")

            // Cleared first, and deliberately. "if not defined" never assigns when the variable is
            // already set, and this helper inherits its environment from the server -- which was itself
            // started by the PREVIOUS helper, which left this variable set. Without the reset each
            // update compares against the hash from the update before it, so the mechanism poisons
            // itself forward and every second update refuses a mismatch that is not real.
            .AppendLine("set \"WINDIAG_STAGED_HASH=\"")
            .AppendLine($"for /f \"skip=1 tokens=* delims=\" %%H in ('certutil -hashfile \"{staged}\" SHA256') do (")
            .AppendLine("  if not defined WINDIAG_STAGED_HASH set \"WINDIAG_STAGED_HASH=%%H\"")
            .AppendLine(")")
            .AppendLine("set \"WINDIAG_STAGED_HASH=!WINDIAG_STAGED_HASH: =!\"")
            .AppendLine($"if /i not \"!WINDIAG_STAGED_HASH!\"==\"{sha256}\" (")
            .AppendLine($"  >>\"{log}\" echo [%time%] ABORT hash mismatch: !WINDIAG_STAGED_HASH!")

            // A failed update must NOT leave the machine with no server. The live executable is
            // untouched at this point, so put it back up -- otherwise a refused update costs a trip to
            // the console, which is the exact thing this mechanism exists to avoid.
            .AppendLine($"  >>\"{log}\" echo [%time%] restarting the existing build instead")
            .AppendLine($"  start \"windiag\" \"{live}\" {arguments}")
            .AppendLine("  exit /b 2")
            .AppendLine(")")
            .AppendLine($"move /y \"{staged}\" \"{live}\" >nul")
            .AppendLine("if errorlevel 1 (")
            .AppendLine($"  >>\"{log}\" echo [%time%] ABORT move failed; restarting the existing build")
            .AppendLine($"  start \"windiag\" \"{live}\" {arguments}")
            .AppendLine("  exit /b 3")
            .AppendLine(")")
            .AppendLine($">>\"{log}\" echo [%time%] swapped; relaunching")
            .AppendLine($"start \"windiag\" \"{live}\" {arguments}")
            .AppendLine($">>\"{log}\" echo [%time%] done")
            .ToString();

        File.WriteAllText(helper, script, Encoding.ASCII);

        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c \"{helper}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(live)!
        });

        _logger.LogInformation("self-update helper started, logging to {Log}", log);
    }

    private static string Quote(string argument) =>
        argument.Contains(' ', StringComparison.Ordinal) ? $"\"{argument}\"" : argument;
}
