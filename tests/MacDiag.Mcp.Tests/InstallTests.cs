using MacDiag.Mcp.Hosting;

namespace MacDiag.Mcp.Tests;

public sealed class InstallTests
{
    private static MacServiceInstallOptions Parse(params string[] args) => MacServiceInstallOptions.Parse(args, new StringReader(""));

    [Fact]
    public void An_address_is_required_and_the_token_is_generated_when_not_given()
    {
        Assert.Throws<ConfigurationException>(() => Parse("--install-service"));
        var options = Parse("--install-service", "--http", "http://0.0.0.0:4025");

        Assert.False(options.TokenWasSupplied);
        Assert.True(options.Token.Length >= 32);
    }

    [Fact]
    public void The_token_can_come_from_standard_input_but_not_from_both_places()
    {
        var options = MacServiceInstallOptions.Parse(["--install-service", "--http", "http://0.0.0.0:4025", "--token-stdin"], new StringReader("t0k\n"));

        Assert.Equal("t0k", options.Token);
        Assert.Throws<ConfigurationException>(() => MacServiceInstallOptions.Parse(
            ["--install-service", "--http", "http://0.0.0.0:4025", "--token-stdin", "--token", "x"], new StringReader("t0k\n")));
    }

    [Theory]
    [InlineData("com.windiag.macdiag", true)]
    [InlineData("com.windiag.macdiag-2", true)]
    [InlineData("../evil", false)]
    [InlineData(".hidden", false)]
    [InlineData("a/b", false)]
    [InlineData("", false)]
    public void The_label_may_hold_only_characters_that_cannot_escape_the_paths_it_names(string label, bool valid)
    {
        if (valid)
        {
            Assert.Equal(label, MacServiceInstallOptions.Label(["--label", label]));
        }
        else
        {
            Assert.Throws<ConfigurationException>(() => MacServiceInstallOptions.Label(["--label", label]));
        }
    }

    [Fact]
    public void The_env_file_holds_the_token_bind_label_and_only_the_grants_given()
    {
        var env = Parse("--install-service", "--http", "http://0.0.0.0:4025", "--token", "t0k", "--allow-self-update").EnvironmentFile();

        Assert.Contains("MACDIAG_TOKEN=t0k\n", env, StringComparison.Ordinal);
        Assert.Contains("MACDIAG_HTTP_BIND=http://0.0.0.0:4025\n", env, StringComparison.Ordinal);
        Assert.Contains("MACDIAG_SERVICE_LABEL=com.windiag.macdiag\n", env, StringComparison.Ordinal);
        Assert.Contains("MACDIAG_ALLOW_SELF_UPDATE=1\n", env, StringComparison.Ordinal);
        Assert.DoesNotContain("COMMAND_EXECUTION", env, StringComparison.Ordinal);
    }

    [Fact]
    public void The_plist_runs_the_binary_with_the_env_file_restarts_only_on_failure_and_never_holds_the_token()
    {
        var options = Parse("--install-service", "--http", "http://0.0.0.0:4025", "--token", "secret-token");
        var plist = options.Plist("/Library/PrivilegedHelperTools/com.windiag.macdiag/MacDiag.Mcp");

        Assert.Contains("<key>Label</key>\n\t<string>com.windiag.macdiag</string>", plist, StringComparison.Ordinal);
        Assert.Contains("<string>--env-file</string>", plist, StringComparison.Ordinal);
        Assert.Contains("<string>/etc/macdiag/macdiag.env</string>", plist, StringComparison.Ordinal);
        Assert.Contains("<key>SuccessfulExit</key>\n\t\t<false/>", plist, StringComparison.Ordinal);
        Assert.Contains("<key>AbandonProcessGroup</key>\n\t<true/>", plist, StringComparison.Ordinal);
        Assert.Contains("<key>ProcessType</key>\n\t<string>Standard</string>", plist, StringComparison.Ordinal);
        Assert.Contains("<string>/var/log/macdiag/crash.log</string>", plist, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-token", plist, StringComparison.Ordinal);
        Assert.DoesNotContain("\r", plist, StringComparison.Ordinal);
    }

    [Fact]
    public void The_plist_escapes_a_path_that_holds_xml_markup()
    {
        var plist = Parse("--install-service", "--http", "http://0.0.0.0:4025").Plist("/tmp/a&b<c>/MacDiag.Mcp");

        Assert.Contains("<string>/tmp/a&amp;b&lt;c&gt;/MacDiag.Mcp</string>", plist, StringComparison.Ordinal);
    }

    [Fact]
    public void The_job_is_booted_out_enabled_then_bootstrapped_in_that_order()
    {
        // A disabled job refuses to bootstrap, and a loaded one must go before it is loaded again.
        Assert.Equal(
            [["bootout", "system/com.windiag.macdiag"], ["enable", "system/com.windiag.macdiag"],
             ["bootstrap", "system", "/Library/LaunchDaemons/com.windiag.macdiag.plist"]],
            MacServiceInstaller.BringUpCommands("com.windiag.macdiag", "/Library/LaunchDaemons/com.windiag.macdiag.plist"));
    }

    [Fact]
    public void The_running_pid_is_read_from_launchctl_print_and_absent_when_the_job_is_not_running()
    {
        Assert.Equal(4242, MacServiceInstaller.PidFrom("system/com.windiag.macdiag = {\n\tactive count = 1\n\tstate = running\n\tpid = 4242\n}"));
        Assert.Null(MacServiceInstaller.PidFrom("system/com.windiag.macdiag = {\n\tstate = not running\n}"));
    }

    [Fact]
    public void A_job_that_loads_but_never_listens_is_reported_as_failed_with_the_logs_last_lines()
    {
        // Review Focus 5: launchd has no readiness signal, so "bootstrap returned 0" proves nothing.
        var (code, message) = MacServiceInstaller.Outcome(listening: false, "com.windiag.macdiag", "http://0.0.0.0:4025", "line 1\nfatal: bind failed");

        Assert.Equal(4, code);
        Assert.Contains("fatal: bind failed", message, StringComparison.Ordinal);
        Assert.Equal(0, MacServiceInstaller.Outcome(listening: true, "com.windiag.macdiag", "http://0.0.0.0:4025", "").Code);
    }

    [Theory]
    [InlineData("http://0.0.0.0:4025", "127.0.0.1", 4025)]
    [InlineData("http://+:4025", "127.0.0.1", 4025)]
    [InlineData("http://*:4025", "127.0.0.1", 4025)]
    [InlineData("http://mac1.lan:7000", "mac1.lan", 7000)]
    public void The_port_wait_connects_to_loopback_for_a_wildcard_bind(string bind, string host, int port)
    {
        Assert.Equal((host, port), MacServiceInstaller.ProbeAddress(bind));
    }

    [Fact]
    public void Uninstall_reports_removed_only_when_the_job_was_there_and_booting_it_out_worked()
    {
        Assert.Equal(1, MacServiceInstaller.UninstallOutcome("com.windiag.macdiag", plistExisted: false, bootoutExit: 0).Code);
        Assert.Equal(4, MacServiceInstaller.UninstallOutcome("com.windiag.macdiag", plistExisted: true, bootoutExit: 5).Code);
        Assert.Equal(0, MacServiceInstaller.UninstallOutcome("com.windiag.macdiag", plistExisted: true, bootoutExit: 0).Code);
    }
}
