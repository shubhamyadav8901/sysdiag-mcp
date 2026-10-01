using Diag.Mcp.Server.SelfUpdate;
using MacDiag.Mcp.Diagnostics.SelfUpdate;
using MacDiag.Mcp.Hosting;

namespace MacDiag.Mcp.Tests;

public sealed class RestartHelperTests
{
    private const string Live = "/Library/PrivilegedHelperTools/com.windiag.macdiag/MacDiag.Mcp";
    private const string Staged = Live + ".new";
    private const string Label = "com.windiag.macdiag";

    private static string UnderLaunchd(bool probe = true) =>
        LaunchdRestartHelper.Script(4242, Live, Staged, "ABC123", "/var/db/macdiag/self-update.log", Label,
            probe ? ("127.0.0.1", 4025) : null, ["--env-file", "/etc/macdiag/com.windiag.macdiag.env"]);

    private static string ByHand() =>
        LaunchdRestartHelper.Script(4242, Live, Staged, "ABC123", "/var/db/macdiag/self-update.log", label: null,
            ("127.0.0.1", 4025), ["--http", "http://0.0.0.0:4025"]);

    [Theory]
    [InlineData("com.windiag.macdiag", "com.windiag.macdiag", 1, true)]
    [InlineData("com.windiag.macdiag", "com.windiag.macdiag", 812, false)]   // started from a launchd job's shell
    [InlineData("com.windiag.macdiag", "com.apple.Terminal", 1, false)]
    [InlineData(null, "com.windiag.macdiag", 1, false)]
    [InlineData("com.windiag.macdiag", null, 1, false)]
    public void Our_launchd_job_means_the_label_matches_and_launchd_is_the_parent(string? label, string? xpcServiceName, int parent, bool ours)
    {
        Assert.Equal(ours, LaunchdJob.Matches(label, xpcServiceName, parent));
    }

    [Fact]
    public void A_quote_in_any_value_is_refused_rather_than_escaped()
    {
        Assert.Throws<SelfUpdateRejectedException>(() => LaunchdRestartHelper.ShellQuote("/tmp/it's"));
        Assert.Equal("'/tmp/x y'", LaunchdRestartHelper.ShellQuote("/tmp/x y"));
    }

    [Fact]
    public void Under_launchd_the_swap_waits_rechecks_backs_up_moves_then_kickstarts_in_that_order()
    {
        var script = UnderLaunchd();

        string[] steps =
        [
            "while kill -0 4242",
            "shasum -a 256 '" + Staged + "'",
            "ln -f '" + Live + "' '" + Live + ".old'",
            "mv -f '" + Staged + "' '" + Live + "'",
            "chmod 0755 '" + Live + "'",
            "launchctl kickstart -k 'system/" + Label + "'",
        ];
        var positions = steps.Select(step => script.IndexOf(step, StringComparison.Ordinal)).ToList();

        Assert.All(positions, p => Assert.True(p >= 0, script));
        Assert.Equal(positions.Order(), positions);
    }

    [Theory]
    [InlineData("hash mismatch", 2)]
    [InlineData("backup failed", 3)]
    [InlineData("move failed", 4)]
    public void Every_failure_before_the_swap_starts_the_existing_build_again(string reason, int exitCode)
    {
        // The server exited 0, so launchd will not restart it on its own: an abort that only exits leaves no server.
        var branch = Branch(UnderLaunchd(), reason);

        Assert.Contains("launchctl kickstart 'system/" + Label + "'", branch, StringComparison.Ordinal);
        Assert.Contains($"exit {exitCode}", branch, StringComparison.Ordinal);
    }

    [Fact]
    public void The_new_build_is_confirmed_by_a_new_pid_its_hash_and_the_port_and_rolled_back_otherwise()
    {
        var script = UnderLaunchd();

        Assert.Contains("launchctl print 'system/" + Label + "'", script, StringComparison.Ordinal);
        Assert.Contains("nc -z -G 2 '127.0.0.1' 4025", script, StringComparison.Ordinal);
        var rollback = Branch(script, "ROLLBACK");
        Assert.Contains("mv -f '" + Live + ".old' '" + Live + "'", rollback, StringComparison.Ordinal);
        Assert.Contains("launchctl kickstart -k 'system/" + Label + "'", rollback, StringComparison.Ordinal);
        Assert.Contains("exit 5", rollback, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_program_is_run_by_its_absolute_system_path()
    {
        var script = UnderLaunchd() + ByHand();

        foreach (var program in new[] { "/usr/bin/shasum", "/bin/launchctl", "/usr/bin/nc", "/bin/ln", "/bin/mv", "/bin/chmod", "/usr/bin/nohup" })
        {
            Assert.Contains(program + " ", script, StringComparison.Ordinal);
        }

        Assert.DoesNotContain("$(shasum", script, StringComparison.Ordinal);
        Assert.DoesNotContain("\n  launchctl", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Without_an_http_address_there_is_no_port_to_check()
    {
        Assert.DoesNotContain("nc -z", UnderLaunchd(probe: false), StringComparison.Ordinal);
    }

    [Fact]
    public void Run_by_hand_it_relaunches_the_binary_itself_and_never_touches_launchd()
    {
        var script = ByHand();

        Assert.DoesNotContain("launchctl", script, StringComparison.Ordinal);
        Assert.Contains("nohup '" + Live + "' '--http' 'http://0.0.0.0:4025' >/dev/null 2>&1 &", script, StringComparison.Ordinal);
    }

    [UnixFact]
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    public void Both_scripts_are_valid_sh()
    {
        foreach (var script in new[] { UnderLaunchd(), UnderLaunchd(probe: false), ByHand() })
        {
            var path = Path.Combine(Path.GetTempPath(), $"helper-{Guid.NewGuid():N}.sh");
            try
            {
                File.WriteAllText(path, script);
                using var check = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("/bin/sh", ["-n", path])
                {
                    RedirectStandardError = true,
                    UseShellExecute = false,
                })!;
                var errors = check.StandardError.ReadToEnd();
                check.WaitForExit();

                Assert.True(check.ExitCode == 0, errors + "\n" + script);
            }
            finally
            {
                File.Delete(path);
            }
        }
    }

    /// <summary>The lines of the if-block whose log message names <paramref name="reason"/>.</summary>
    private static string Branch(string script, string reason)
    {
        var start = script.IndexOf(reason, StringComparison.Ordinal);
        Assert.True(start >= 0, script);
        var end = script.IndexOf("\nfi", start, StringComparison.Ordinal);
        return script[start..end];
    }
}
