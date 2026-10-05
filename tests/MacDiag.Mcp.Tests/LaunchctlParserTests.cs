using MacDiag.Mcp.Mac.Parsers;
using static MacDiag.Mcp.Tests.SystemOverviewTests;

namespace MacDiag.Mcp.Tests;

public sealed class LaunchctlParserTests
{
    [Fact]
    public void Only_the_jobs_own_keys_are_read_and_a_nested_block_cannot_speak_for_it()
    {
        // Review Focus 5: endpoints holds its own "state = active" and "pid = 999"; neither is the job's.
        var keys = LaunchctlPrint.TopLevel(Fixture(Unverified, "launchctl-print-sshd"));

        Assert.Equal("not running", keys["state"]);
        Assert.Equal("/System/Library/LaunchDaemons/ssh.plist", keys["path"]);
        Assert.False(keys.ContainsKey("pid"));
        Assert.False(keys.ContainsKey("port"));
        Assert.Equal("daemon (3)", keys["spawn type"]);
    }

    [Fact]
    public void Job_state_comes_from_the_top_level_keys_and_a_job_that_never_exited_has_no_exit_code()
    {
        var state = LaunchctlPrint.State(Fixture(Unverified, "launchctl-print-sshd"));

        Assert.Equal("not running", state.State);
        Assert.Null(state.ProcessId);
        Assert.Null(state.LastExitCode);
        Assert.Equal("(never exited)", state.LastExitText);
        Assert.Equal(0, state.Runs);
        Assert.Equal("/usr/libexec/sshd-keygen-wrapper", state.Program);
        Assert.Empty(state.Missing);
    }

    [Fact]
    public void A_running_job_gives_its_pid_and_an_exit_code_with_its_name_keeps_both()
    {
        var state = LaunchctlPrint.State("system/x = {\n\tstate = running\n\tpid = 4242\n\tlast exit code = 78: EX_CONFIG\n\tlast terminating signal = Killed: 9\n\tpath = /Library/LaunchDaemons/x.plist\n}\n");

        Assert.Equal(("running", 4242, 78, "78: EX_CONFIG", "Killed: 9"), (state.State, state.ProcessId, state.LastExitCode, state.LastExitText, state.LastSignal));
    }

    [Fact]
    public void A_missing_expected_key_is_named_rather_than_guessed()
    {
        var state = LaunchctlPrint.State("system/x = {\n\tstate = running\n}\n");

        Assert.Equal(["path"], state.Missing);
    }

    [Fact]
    public void The_job_list_skips_the_header_and_any_row_in_another_shape()
    {
        var rows = LaunchctlList.Parse(Fixture(Unverified, "launchctl-list"));

        Assert.Equal(5, rows.Count);
        Assert.Contains(rows, r => r.Label == "com.openssh.sshd" && r.ProcessId == 777);
        Assert.Contains(rows, r => r.Label == "com.apple.ftp-proxy" && r.ProcessId is null);
        Assert.Equal("-9", rows.Single(r => r.Label == "com.example.web").Status);
    }

    [Fact]
    public void Print_disabled_as_a_real_mac_indents_it_by_a_tab_is_read_and_stops_at_its_own_block()
    {
        // launchctl print-disabled system on macOS 26.6.2: a blank line, then the whole listing indented by a tab.
        var disabled = LaunchctlDisabled.Parse(
            "\n\tdisabled services = {\n\t\t\"com.apple.ftpd\" => disabled\n\t\t\"com.openssh.sshd\" => enabled\n\t}\n" +
            "\n\tlogin item associations = {\n\t\t\"com.example.helper\" => disabled\n\t}\n");

        Assert.Equal(new Dictionary<string, bool> { ["com.apple.ftpd"] = true, ["com.openssh.sshd"] = false }, disabled);
    }

    [Fact]
    public void Disabled_overrides_read_both_spellings_and_only_from_their_own_block()
    {
        var disabled = LaunchctlDisabled.Parse(Fixture(Unverified, "launchctl-print-disabled"));

        Assert.True(disabled["com.apple.ftp-proxy"]);
        Assert.False(disabled["com.openssh.sshd"]);
        Assert.True(disabled["com.example.old"]);
        Assert.False(disabled["com.example.new"]);
        Assert.False(disabled.ContainsKey("com.example.helper"));
    }
}
