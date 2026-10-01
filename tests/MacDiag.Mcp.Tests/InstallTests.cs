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
        Assert.Contains("<string>/etc/macdiag/com.windiag.macdiag.env</string>", plist, StringComparison.Ordinal);
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
    [InlineData(true, null, 501, true, new[] { 501 }, true)]     // fresh install, the new job is the listener
    [InlineData(true, 400, 501, true, new[] { 501 }, true)]      // reinstall, a new process
    [InlineData(true, null, 501, true, new[] { 77 }, false)]     // something else holds the port
    [InlineData(true, 400, 400, true, new[] { 400 }, false)]     // the old process never went away
    [InlineData(true, 400, null, false, new[] { 77 }, false)]    // the job is not running at all
    [InlineData(true, null, 501, false, new[] { 501 }, false)]   // launchd does not call it running
    [InlineData(false, null, 501, true, new int[0], false)]      // nothing listening
    public void Installed_means_the_new_job_is_running_and_is_the_process_listening(
        bool portOpen, int? oldPid, int? newPid, bool running, int[] listeners, bool installed)
    {
        // Review Focus 5: a by-hand server left on the port, or the previous process, must not pass for the new job.
        Assert.Equal(installed, MacServiceInstaller.IsInstalled(portOpen, oldPid, newPid, running, listeners));
    }

    [Fact]
    public void Lsof_terse_output_gives_the_listening_pids()
    {
        Assert.Equal([501, 77], MacServiceInstaller.ParsePids("501\n77\n\nnot-a-pid\n"));
    }

    [Fact]
    public void Launchctl_print_says_whether_the_job_is_running()
    {
        Assert.True(MacServiceInstaller.IsRunning("system/x = {\n\tstate = running\n\tpid = 1\n}"));
        Assert.False(MacServiceInstaller.IsRunning("system/x = {\n\tstate = not running\n}"));
    }

    [Fact]
    public void The_unload_wait_outlasts_the_stop_window_the_plist_gives_launchd()
    {
        // A busy daemon takes up to ExitTimeOut to stop; giving up sooner left the files replaced and nothing loaded.
        var plist = Parse("--install-service", "--http", "http://0.0.0.0:4025").Plist("/x/MacDiag.Mcp");

        Assert.Contains($"<key>ExitTimeOut</key>\n\t<integer>{(int)MacServiceInstallOptions.ExitTimeOut.TotalSeconds}</integer>", plist, StringComparison.Ordinal);
        Assert.True(MacServiceInstaller.UnloadBudget > MacServiceInstallOptions.ExitTimeOut + TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void Each_label_has_its_own_settings_file_so_a_second_install_never_touches_the_first()
    {
        var a = Parse("--install-service", "--http", "http://0.0.0.0:4025");
        var b = Parse("--install-service", "--http", "http://0.0.0.0:4026", "--label", "com.windiag.macdiag-2");

        Assert.Equal("/etc/macdiag/com.windiag.macdiag.env", a.EnvironmentFilePath);
        Assert.Equal("/etc/macdiag/com.windiag.macdiag-2.env", b.EnvironmentFilePath);
        Assert.Contains("<string>/etc/macdiag/com.windiag.macdiag-2.env</string>", b.Plist("/x/MacDiag.Mcp"), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false, 0, 0, StartupPermissions.EntryKind.Directory, null)]          // created by the installer
    [InlineData(true, 0, 0b111_000_000, StartupPermissions.EntryKind.Directory, null)]
    [InlineData(true, 0, 0b111_101_101, StartupPermissions.EntryKind.Directory, null)]
    [InlineData(true, 0, 0b1_111_111_111, StartupPermissions.EntryKind.Directory, "sticky")]  // /tmp
    [InlineData(true, 0, 0b111_111_101, StartupPermissions.EntryKind.Directory, "group")]
    [InlineData(true, 501, 0b111_000_000, StartupPermissions.EntryKind.Directory, "uid 501")]  // /Users/someone
    [InlineData(true, 0, 0b110_100_100, StartupPermissions.EntryKind.File, "not a directory")]
    public void An_existing_artifact_directory_is_used_only_if_root_alone_controls_it_and_is_never_rechmodded(
        bool existed, int uid, int mode, StartupPermissions.EntryKind kind, string? problem)
    {
        // --artifacts /tmp once chmodded /private/tmp to 0700, breaking every other account on the Mac.
        var found = MacServiceInstaller.ArtifactDirectoryProblem(existed, new StartupPermissions.StatEntry("/some/dir", uid, mode, kind));

        if (problem is null)
        {
            Assert.Null(found);
        }
        else
        {
            Assert.Contains(problem, found, StringComparison.Ordinal);
        }
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
