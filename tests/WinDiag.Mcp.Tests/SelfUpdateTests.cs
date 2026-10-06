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
    public void The_helper_script_is_a_new_file_never_one_already_at_that_name_rewritten_in_place()
    {
        // A self-update.cmd left by a user while the artifact directory was writable stays theirs if it is
        // truncated and rewritten: same owner, same DACL, and any handle they hold still writes to it -- and
        // cmd re-reads a batch file as it runs, for minutes while the helper waits for the server to exit.
        // A handle held on the old file stands in for that user here: it must not see the helper's text.
        var helper = Path.Combine(_directory, "self-update.cmd");
        File.WriteAllText(helper, "planted");
        using var held = new FileStream(helper, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

        WindowsRestartHelper.WriteScript(helper, "@echo off\r\n");

        Assert.Equal("@echo off\r\n", File.ReadAllText(helper));
        using var reader = new StreamReader(held);
        Assert.Equal("planted", reader.ReadToEnd());
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

/// <summary>
/// What the Windows ratchet accepts, decided from scripted signatures so every case is reachable.
/// </summary>
/// <remarks>
/// The real WinTrust inspector cannot produce most of these on demand -- an expired, untimestamped
/// signature on the running build, or a validly signed file from a second publisher -- and those are
/// exactly the cases that were wrong.
/// </remarks>
public sealed class WindowsSignatureRatchetTests
{
    private const string Live = @"C:\WinDiag\WinDiag.Mcp.exe";
    private const string Contoso = "CN=Contoso Ltd, O=Contoso Ltd, L=Redmond, S=Washington, C=US";
    private const string Fabrikam = "CN=Fabrikam Inc, O=Fabrikam Inc, C=US";
    private const string MicrosoftWindows = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";

    private static FileSignature Signature(string path, SignatureVerdict verdict, string? subject) =>
        new(path, verdict, $"{verdict}.", false, null, null, null, null, null, null, null, 1,
            DateTimeOffset.UnixEpoch, "AB", subject);

    private static StagedBuild Staged(string verdict, string? signer) =>
        new(@"C:\WinDiag\next.exe", "AB", 1, verdict, verdict == "Valid" ? null : "detail.", signer);

    private static WindowsSignatureRatchet Ratchet(SignatureVerdict liveVerdict, string? liveSubject) =>
        new(new ScriptedSignatureInspector(Signature(Live, liveVerdict, liveSubject)),
            NullLogger<WindowsSignatureRatchet>.Instance);

    [Fact]
    public void Refuses_a_validly_signed_replacement_from_another_publisher()
    {
        // "Validly signed" alone let the token install any publisher's binary -- a verbatim copy of a
        // catalog-signed Windows executable included -- for the service to run as SYSTEM.
        var ex = Assert.Throws<SelfUpdateRejectedException>(
            () => Ratchet(SignatureVerdict.Valid, Contoso)
                .RequireAcceptable(Live, Staged("Valid", MicrosoftWindows), CancellationToken.None));

        Assert.Contains("same publisher", ex.Message);
        Assert.Contains(MicrosoftWindows, ex.Message);
        Assert.Contains("Nothing has been changed", ex.Message);
    }

    [Fact]
    public void Refuses_a_validly_signed_replacement_whose_signer_could_not_be_read()
    {
        Assert.Throws<SelfUpdateRejectedException>(
            () => Ratchet(SignatureVerdict.Valid, Contoso)
                .RequireAcceptable(Live, Staged("Valid", null), CancellationToken.None));
    }

    [Fact]
    public void Accepts_a_validly_signed_replacement_from_the_same_publisher()
    {
        Ratchet(SignatureVerdict.Valid, Contoso)
            .RequireAcceptable(Live, Staged("Valid", Contoso), CancellationToken.None);
    }

    [Theory]
    [InlineData(SignatureVerdict.Untrusted)]
    [InlineData(SignatureVerdict.Unknown)]
    public void Stays_engaged_when_the_running_builds_signature_no_longer_verifies(SignatureVerdict live)
    {
        // It used to switch itself off for anything but Valid, so an expired untimestamped signature, or
        // one that had stopped matching its file, let an unsigned replacement straight through.
        Assert.Throws<SelfUpdateRejectedException>(
            () => Ratchet(live, Contoso).RequireAcceptable(Live, Staged("Unsigned", null), CancellationToken.None));
        Assert.Throws<SelfUpdateRejectedException>(
            () => Ratchet(live, Contoso).RequireAcceptable(Live, Staged("Valid", Fabrikam), CancellationToken.None));

        // The way out of an expired certificate is still open: a properly signed build from the same
        // publisher.
        Ratchet(live, Contoso).RequireAcceptable(Live, Staged("Valid", Contoso), CancellationToken.None);
    }

    [Fact]
    public void Refuses_everything_when_the_running_build_is_signed_by_someone_it_cannot_name()
    {
        var ex = Assert.Throws<SelfUpdateRejectedException>(
            () => Ratchet(SignatureVerdict.Unknown, null)
                .RequireAcceptable(Live, Staged("Valid", Contoso), CancellationToken.None));

        Assert.Contains("no publisher to hold a replacement to", ex.Message);
    }

    [Fact]
    public void Leaves_an_unsigned_development_build_free_to_take_anything()
    {
        Ratchet(SignatureVerdict.Unsigned, null)
            .RequireAcceptable(Live, Staged("Unsigned", null), CancellationToken.None);
    }

    [Fact]
    public void Carries_the_signer_read_in_the_same_held_inspection_as_the_hash()
    {
        var inspector = new ScriptedSignatureInspector(Signature(Live, SignatureVerdict.Valid, Contoso))
        {
            Held = Signature(@"C:\WinDiag\next.exe", SignatureVerdict.Valid, Fabrikam)
        };

        var staged = new WindowsStagedBuildInspector(inspector).Inspect(@"C:\WinDiag\next.exe", CancellationToken.None);

        Assert.Equal(Fabrikam, staged.SignerIdentity);
        Assert.Equal(1, inspector.HeldCalls);
        Assert.Equal(0, inspector.UnheldCalls);
    }

    [Fact]
    public void Refuses_a_staged_build_something_still_has_open_for_writing()
    {
        var inspector = new ScriptedSignatureInspector(Signature(Live, SignatureVerdict.Valid, Contoso))
        {
            HeldFailure = new IOException("The process cannot access the file because it is being used by another process.")
        };

        var ex = Assert.Throws<SelfUpdateRejectedException>(
            () => new WindowsStagedBuildInspector(inspector).Inspect(@"C:\WinDiag\next.exe", CancellationToken.None));

        Assert.Contains("writers locked out", ex.Message);
        Assert.Contains("Nothing has been changed", ex.Message);
    }

    /// <summary>Answers every unheld inspection with one signature, and a held one as scripted.</summary>
    private sealed class ScriptedSignatureInspector(FileSignature answer) : ISignatureInspector
    {
        public FileSignature? Held { get; init; }

        public Exception? HeldFailure { get; init; }

        public int HeldCalls { get; private set; }

        public int UnheldCalls { get; private set; }

        public SignatureQueryResult Inspect(IReadOnlyList<string> paths, CancellationToken cancellationToken)
        {
            UnheldCalls++;
            return new SignatureQueryResult([answer], []);
        }

        public FileSignature InspectHeld(string path, CancellationToken cancellationToken)
        {
            HeldCalls++;
            return HeldFailure is { } failure ? throw failure : Held ?? answer;
        }
    }
}

/// <summary>The held inspection against the real WinTrust inspector and a real file. Windows only.</summary>
public sealed class HeldSignatureInspectionTests
{
    [Fact]
    public void Refuses_to_inspect_a_staged_file_another_handle_has_open_for_writing()
    {
        // A sharing violation is the whole mechanism: while this inspection can open the file, nothing
        // can be writing it, so the verdict and the hash it returns describe the same bytes.
        var path = Path.Combine(Path.GetTempPath(), $"windiag-held-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(path, "not a real build"u8.ToArray());

        try
        {
            using (new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
            {
                Assert.Throws<SelfUpdateRejectedException>(
                    () => new WindowsStagedBuildInspector(new WinTrustSignatureInspector())
                        .Inspect(path, CancellationToken.None));
            }

            // And once the writer has gone, the same file inspects normally.
            var staged = new WindowsStagedBuildInspector(new WinTrustSignatureInspector()).Inspect(path, CancellationToken.None);
            Assert.Equal(Convert.ToHexString(SHA256.HashData("not a real build"u8.ToArray())), staged.Sha256);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Names_the_publisher_of_signed_system_binaries_from_the_verified_signature()
    {
        // From WinVerifyTrust's own state, catalog signatures included -- which carry no embedded
        // certificate at all, so a reading of the file's certificate bag would name nobody.
        var sample = Directory.EnumerateFiles(Environment.SystemDirectory, "*.dll").Take(30).ToArray();

        var valid = new WinTrustSignatureInspector().Inspect(sample, CancellationToken.None).Files
            .Where(f => f.Verdict == SignatureVerdict.Valid)
            .ToList();

        Assert.NotEmpty(valid);
        Assert.All(valid, f => Assert.Contains("O=Microsoft Corporation", f.SignerSubject));
    }
}
