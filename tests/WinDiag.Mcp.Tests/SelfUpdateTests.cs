using System.Collections;
using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.SelfUpdate;
using WinDiag.Mcp.Diagnostics.Signatures;

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

    private SelfUpdater Updater() =>
        new(
            new WinTrustSignatureInspector(),
            WinDiagOptions.FromEnvironment(new Hashtable { ["WINDIAG_ARTIFACT_DIR"] = _directory }),
            new StubLifetime(),
            NullLogger<SelfUpdater>.Instance);

    [Fact]
    public void Refuses_a_staged_name_that_is_a_path()
    {
        // A caller must never be able to steer this at a file outside the server's own directory:
        // that would turn "install my update" into "run anything on disk as SYSTEM".
        foreach (var name in (string[])[@"..\evil.exe", @"C:\Windows\Temp\evil.exe", "sub/dir.exe"])
        {
            var ex = Assert.Throws<SelfUpdateRejectedException>(
                () => Updater().Update(new string('a', 64), name, CancellationToken.None));

            Assert.Contains("file name, not a path", ex.Message);
        }
    }

    [Fact]
    public void Refuses_when_nothing_is_staged()
    {
        var ex = Assert.Throws<SelfUpdateRejectedException>(
            () => Updater().Update(new string('a', 64), "does-not-exist.exe", CancellationToken.None));

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
                () => Updater().Update(new string('a', 64), Path.GetFileName(staged), CancellationToken.None));

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
        // Hashes get copied out of tooling in several shapes; rejecting on formatting alone would only
        // train callers to paste less carefully.
        var payload = "windiag test payload"u8.ToArray();
        var staged = StageBesideTheServer("windiag-test-staged2.exe", payload);
        var sha = Convert.ToHexString(SHA256.HashData(payload));

        try
        {
            // Not a real server executable, so it cannot get as far as swapping - but it must get PAST
            // the hash check, which a formatting rejection would not.
            foreach (var form in (string[])[sha, sha.ToLowerInvariant(), string.Join('-', sha.Chunk(2).Select(c => new string(c)))])
            {
                var ex = Record.Exception(
                    () => Updater().Update(form, Path.GetFileName(staged), CancellationToken.None));

                if (ex is SelfUpdateRejectedException rejected)
                {
                    Assert.DoesNotContain("does not match the hash", rejected.Message);
                }
            }
        }
        finally
        {
            File.Delete(staged);
        }
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
