using System.Collections;
using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using WinDiag.Mcp.Configuration;
using Diag.Mcp.Server.SelfUpdate;
using WinDiag.Mcp.Diagnostics.SelfUpdate;
using WinDiag.Mcp.Diagnostics.Signatures;
using WinDiag.Mcp.Hosting;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// Covers what <c>update_self</c> REFUSES.
/// </summary>
/// <remarks>
/// This is the most dangerous code in the project: it replaces an elevated executable and runs it, so
/// the bearer token effectively guards arbitrary code execution wherever it is enabled. The happy path
/// is the least interesting thing about it — every test here is a rejection, because a rejection that
/// stops working is how this becomes a backdoor.
/// </remarks>
public sealed class SelfUpdateRejectionTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"windiag-selfupdate-{Guid.NewGuid():N}");

    public SelfUpdateRejectionTests() => Directory.CreateDirectory(_directory);

    /// <summary>The activity tracker the updater under test reports to, so a test can inspect it.</summary>
    private readonly ToolActivity _activity = new();

    /// <summary>The shared engine with this server's real inspector, ratchet and helper.</summary>
    private SelfUpdater Updater()
    {
        var options = WinDiagOptions.FromEnvironment(new Hashtable { ["WINDIAG_ARTIFACT_DIR"] = _directory });
        var signatures = new WinTrustSignatureInspector();

        return new(
            new WindowsStagedBuildInspector(signatures),
            new WindowsSignatureRatchet(signatures, NullLogger<WindowsSignatureRatchet>.Instance),
            new WindowsRestartHelper(options, NullLogger<WindowsRestartHelper>.Instance),
            new SelfUpdateOptions(options.ArtifactDirectory, options.UpdateDrainTimeout),
            new StubLifetime(),
            _activity,
            NullLogger<SelfUpdater>.Instance);
    }

    [Fact]
    public void Refuses_a_staged_name_that_is_a_path()
    {
        // A caller must never be able to steer this at a file outside the server's own directory:
        // that would turn "install my update" into "run anything on disk as SYSTEM".
        foreach (var name in (string[])[@"..\evil.exe", @"C:\Windows\Temp\evil.exe", "sub/dir.exe"])
        {
            var ex = Assert.Throws<SelfUpdateRejectedException>(
                () => Updater().Update(new string('a', 64), name, force: false, CancellationToken.None));

            Assert.Contains("file name, not a path", ex.Message);
        }
    }

    [Fact]
    public void Refuses_when_nothing_is_staged()
    {
        var ex = Assert.Throws<SelfUpdateRejectedException>(
            () => Updater().Update(new string('a', 64), "does-not-exist.exe", force: false, CancellationToken.None));

        Assert.Contains("No staged build", ex.Message);
    }

    [Fact]
    public void Refuses_a_staged_file_whose_hash_does_not_match()
    {
        // The check that catches a corrupted transfer. A copy of the real build reached a target at
        // exactly the right size and was corrupt, twice; only the hash noticed.
        var staged = StageBesideTheServer("windiag-test-staged.exe", "not the build you asked for"u8.ToArray());

        try
        {
            var ex = Assert.Throws<SelfUpdateRejectedException>(
                () => Updater().Update(new string('a', 64), Path.GetFileName(staged), force: false, CancellationToken.None));

            Assert.Contains("does not match the hash you gave", ex.Message);
            Assert.Contains("Nothing has been changed", ex.Message);
        }
        finally
        {
            File.Delete(staged);
        }
    }

    [Fact]
    public void Accepts_the_hash_in_either_case_and_with_separators()
    {
        // Hashes get copied out of certutil, PowerShell and this server's own output in several shapes;
        // rejecting on formatting alone would only train callers to paste less carefully.
        //
        // Tested against the normalisation directly, NOT by calling Update with a matching hash. That
        // route was quietly dangerous: past the hash check the only remaining gate is the signature
        // ratchet, which passes when the running executable is unsigned -- and in a test run the running
        // executable is the test host. So on an unsigned test host it launched a real helper that waited
        // for the test host to exit and then moved a file of test junk over testhost.exe. It survived on
        // timing alone.
        var sha = Convert.ToHexString(SHA256.HashData("windiag test payload"u8.ToArray()));

        Assert.Equal(sha, SelfUpdater.NormalizeHash(sha));
        Assert.Equal(sha, SelfUpdater.NormalizeHash($"  {sha}\t"));
        Assert.Equal(sha, SelfUpdater.NormalizeHash(string.Join('-', sha.Chunk(2).Select(c => new string(c)))));

        // Case is not normalised here because the comparison itself is case-insensitive; asserting the
        // pair together is what shows lower-case input still matches.
        Assert.Equal(sha, SelfUpdater.NormalizeHash(sha.ToLowerInvariant()), StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_registered_service_is_restarted_through_the_scm_not_by_launching_the_exe()
    {
        // Launching the executable would start a process the SCM knows nothing about: the service reads
        // as Stopped while something holds its port, and service_control start then fails because the
        // port is taken. A machine in a state nobody inspecting it would predict -- and since the whole
        // reason to register a service is remote restart, that failure would land precisely when the
        // console visit it was meant to avoid is hardest to make.
        var command = WindowsRestartHelper.RelaunchCommand("windiag", @"C:\WinDiag\WinDiag.Mcp.exe", "--http http://x:4024");

        Assert.Equal("sc start \"windiag\"", command);
        Assert.DoesNotContain("WinDiag.Mcp.exe", command, StringComparison.Ordinal);
    }

    [Fact]
    public void A_server_started_by_hand_is_still_restarted_by_launching_the_exe()
    {
        // The path every existing deployment uses. Both arguments and the quoted path have to survive,
        // or the relaunched server comes back without its bind address and listens nowhere.
        var command = WindowsRestartHelper.RelaunchCommand(
            null, @"C:\WinDiag\WinDiag.Mcp.exe", "--http http://192.168.32.93:4024");

        Assert.Equal(
            "start \"windiag\" \"C:\\WinDiag\\WinDiag.Mcp.exe\" --http http://192.168.32.93:4024", command);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void An_unknown_service_name_falls_back_to_launching_the_exe(string serviceName)
    {
        // The name is looked up by process id and that lookup can fail. Falling back to the by-hand
        // behaviour keeps a server running; emitting `sc start ""` would leave the machine with none.
        Assert.StartsWith("start ", WindowsRestartHelper.RelaunchCommand(serviceName, @"C:\w\x.exe", "--http h"),
            StringComparison.Ordinal);
    }

    [Fact]
    public void A_refused_update_never_stops_the_server_accepting_calls()
    {
        // The server now turns callers away while an update is pending, so it can reach idle before it
        // restarts. A REFUSED update must not do that: it would leave a healthy server rejecting
        // everything for half an hour because someone pasted the wrong hash.
        //
        // This also replaces a guard that quietly stopped working. StubLifetime.StopApplication throws
        // to assert "a rejection path must never reach shutdown", but shutdown now runs inside a
        // background task's finally, where that throw would be swallowed unobserved and the test would
        // pass while checking nothing. Asserting on the pending flag tests the real invariant instead.
        Assert.Throws<SelfUpdateRejectedException>(
            () => Updater().Update(new string('a', 64), "does-not-exist.exe", force: false, CancellationToken.None));

        Assert.False(_activity.IsUpdatePending);

        Assert.True(_activity.TryBegin("system_overview", out var refusal));
        Assert.Null(refusal);
        _activity.End();
    }

    /// <summary>
    /// The staged file must sit beside the running executable, which for a test run is the test host.
    /// </summary>
    private static string StageBesideTheServer(string name, byte[] content)
    {
        var path = Path.Combine(Path.GetDirectoryName(Environment.ProcessPath)!, name);
        File.WriteAllBytes(path, content);
        return path;
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
        catch (IOException)
        {
            // Temp reclaims it.
        }
    }

    private sealed class StubLifetime : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => CancellationToken.None;

        public CancellationToken ApplicationStopping => CancellationToken.None;

        public CancellationToken ApplicationStopped => CancellationToken.None;

        public void StopApplication() => throw new InvalidOperationException(
            "a rejection path must never reach shutdown");
    }
}

/// <summary>
/// What the caller is told, which is the only warning they get before the connection drops.
/// </summary>
/// <remarks>
/// The summary is built before the wait begins, so every branch has to be future tense and none of them
/// may claim the drain succeeded. Getting this wrong is not cosmetic: an operator who reconnects on the
/// wrong signal concludes the update failed and retries into a server that is mid-swap.
/// </remarks>
public sealed class SelfUpdateRenderingTests
{
    private static SelfUpdateResult Result(bool forced, int others) =>
        new(
            StagedPath: @"C:\WinDiag\WinDiag.Mcp.new.exe",
            LivePath: @"C:\WinDiag\WinDiag.Mcp.exe",
            SizeBytes: 49_012_297,
            Sha256: new string('E', 64),
            SignatureVerdict: "Unsigned",
            HelperLogPath: @"C:\Temp\windiag\self-update.log",
            RestartScheduled: true,
            Forced: forced,
            OtherCallsInFlight: others,
            DrainTimeoutSeconds: forced ? 0 : 1800);

    [Fact]
    public void An_idle_server_is_still_told_it_comes_back_in_about_ten_seconds()
    {
        // The overwhelmingly common case - a deploy against a target nobody else is using - must read
        // exactly as it always did, or every deploy looks like it changed behaviour.
        var summary = SelfUpdateTools.Render(Result(forced: false, others: 0));

        Assert.Contains("about ten seconds", summary, StringComparison.Ordinal);
        Assert.Contains("CONNECTION WILL DROP", summary, StringComparison.Ordinal);
    }

    [Fact]
    public void A_busy_server_says_it_will_wait_and_how_to_know_when_it_is_back()
    {
        var summary = SelfUpdateTools.Render(Result(forced: false, others: 3));

        Assert.Contains("3 other tool call(s)", summary, StringComparison.Ordinal);
        Assert.Contains("30 minutes", summary, StringComparison.Ordinal);

        // "Wait about ten seconds" would be a lie here, and a caller obeying it would reconnect to the
        // old process and think the update never happened.
        Assert.DoesNotContain("about ten seconds", summary, StringComparison.Ordinal);

        // The refusal is the signal, so the summary has to say so.
        Assert.Contains("stop being refused", summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Forcing_says_plainly_what_it_costs()
    {
        var summary = SelfUpdateTools.Render(Result(forced: true, others: 2));

        Assert.Contains("WITHOUT waiting", summary, StringComparison.Ordinal);
        Assert.Contains("cut off", summary, StringComparison.Ordinal);
        Assert.Contains("orphaned", summary, StringComparison.Ordinal);

        // force is not instant: the host still allows itself time to stop Procmon and friends cleanly,
        // and an operator who is not told that reads the delay as force being broken.
        Assert.Contains("30 seconds", summary, StringComparison.Ordinal);
    }
}

public sealed class SelfUpdateGatingTests
{
    [Fact]
    public void Is_off_unless_explicitly_enabled()
    {
        // Defaulting this on would silently upgrade what the bearer token protects, on every existing
        // deployment, without anyone choosing it.
        Assert.False(WinDiagOptions.FromEnvironment(new Hashtable()).AllowSelfUpdate);
    }

    [Fact]
    public void Is_enabled_only_by_the_documented_spellings()
    {
        var env = new Hashtable { ["WINDIAG_ALLOW_SELF_UPDATE"] = "1" };
        Assert.True(WinDiagOptions.FromEnvironment(env).AllowSelfUpdate);

        env["WINDIAG_ALLOW_SELF_UPDATE"] = "0";
        Assert.False(WinDiagOptions.FromEnvironment(env).AllowSelfUpdate);
    }

    [Fact]
    public void Rejects_a_misspelled_flag_rather_than_defaulting_it_off()
    {
        // Silently reading "ture" as false would leave an operator believing they had enabled it.
        Assert.Throws<ConfigurationException>(
            () => WinDiagOptions.FromEnvironment(new Hashtable { ["WINDIAG_ALLOW_SELF_UPDATE"] = "ture" }));
    }

    [Fact]
    public void Appears_in_the_startup_summary()
    {
        Assert.Contains("allowSelfUpdate=False", WinDiagOptions.FromEnvironment(new Hashtable()).Describe());
    }
}
