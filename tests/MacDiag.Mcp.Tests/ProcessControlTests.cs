using System.Collections;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Control;
using Microsoft.Extensions.Logging.Abstractions;
using static MacDiag.Mcp.Tests.SystemOverviewTests;

namespace MacDiag.Mcp.Tests;

public sealed class ProcessControlTests
{
    private const string Start = "Tue Oct  1 08:00:00 2024";

    private sealed record Proc(int Ppid, string Stat, string Start, string Comm, string Args, int Uid = 0);

    /// <summary>ps, kill and launchctl list over a little process table; kill -s TERM/KILL ends a process.</summary>
    private sealed class Mac
    {
        public Dictionary<int, Proc> Processes { get; } = new()
        {
            [640] = new(1, "S", Start, "/bin/sleep", "/bin/sleep 60"),
            [641] = new(1, "T", Start, "/bin/sleep", "/bin/sleep 60"),
            [642] = new(1, "Z", Start, "/bin/sleep", ""),
            [777] = new(1, "Ss", Start, "/usr/sbin/sshd", "sshd: admin [priv]"),
            [88] = new(1, "Ss", Start, "/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer", "WindowServer -daemon"),
            [1234] = new(1, "Ss", Start, "/usr/local/bin/webd", "/usr/local/bin/webd --port 80"),
            [900] = new(1, "Ss", Start, "/usr/local/bin/renamed", "sshd: admin [priv]"),
        };

        public bool ChangesHandsOnReread { get; init; }

        public bool ListFails { get; init; }

        public bool ListEmpty { get; init; }

        /// <summary>launchctl list in each user's own domain, as launchctl asuser shows it; a uid not here fails.</summary>
        public Dictionary<int, string> UserLists { get; } = [];

        public List<int> AsUser { get; } = [];

        /// <summary>What ps prints for the uid, when it is not the table's number: nobody is -2 or 4294967294.</summary>
        public string? UidText { get; init; }

        public List<string> Signals { get; } = [];

        private int _identityReads;

        public FakeCommands Commands => new((program, args) => program switch
        {
            "ps" => Ps(args),
            "kill" => Kill(args),
            "launchctl" when args[0] == "asuser" => UserList(int.Parse(args[1], System.Globalization.CultureInfo.InvariantCulture)),
            "launchctl" when args[0] == "list" => ListFails ? new ExternalResult(1, "", "launchctl: timed out")
                : ListEmpty ? FakeCommands.Ok("PID\tStatus\tLabel\n")
                : FakeCommands.Ok(Fixture(Unverified, "launchctl-list")),
            _ => new ExternalResult(1, "", $"unexpected {program}"),
        });

        private ExternalResult Ps(IReadOnlyList<string> args)
        {
            var pid = int.Parse(args[args.ToList().IndexOf("-p") + 1], System.Globalization.CultureInfo.InvariantCulture);
            if (!Processes.TryGetValue(pid, out var p))
            {
                return new ExternalResult(1, "", "");
            }

            var columns = args[^1];
            if (columns == "args=")
            {
                return FakeCommands.Ok(p.Args + "\n");
            }

            if (columns == "stat=")
            {
                return FakeCommands.Ok(p.Stat + "\n");
            }

            if (columns == "uid=")
            {
                return FakeCommands.Ok($"  {UidText ?? p.Uid.ToString(System.Globalization.CultureInfo.InvariantCulture)}\n");
            }

            // The re-read just before the signal asks for pid, lstart and comm only.
            var start = columns == "pid=,lstart=,comm=" && ChangesHandsOnReread ? "Tue Oct  1 09:59:59 2024" : p.Start;
            _identityReads++;
            return columns == "pid=,lstart=,comm="
                ? FakeCommands.Ok($"  {pid} {start}     {p.Comm}\n")
                : FakeCommands.Ok($"  {pid}     {p.Ppid} {p.Stat}  {start}     {p.Comm}\n");
        }

        private ExternalResult UserList(int uid)
        {
            AsUser.Add(uid);
            return UserLists.TryGetValue(uid, out var list)
                ? FakeCommands.Ok("PID\tStatus\tLabel\n" + list)
                : new ExternalResult(1, "", $"Could not switch to audit session for uid {uid}");
        }

        private ExternalResult Kill(IReadOnlyList<string> args)
        {
            var signal = args[1];
            var pid = int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture);
            Signals.Add($"{signal} {pid}");
            if (!Processes.ContainsKey(pid))
            {
                return new ExternalResult(1, "", $"kill: {pid}: No such process");
            }

            if (signal is "TERM" or "KILL")
            {
                Processes.Remove(pid);
            }

            return FakeCommands.Ok("");
        }
    }

    private static MacProcessController Controller(Mac mac, string? protectedLabels = null, bool root = true) =>
        new(mac.Commands,
            MacDiagOptions.FromEnvironment(protectedLabels is null ? new Hashtable() : new Hashtable { ["MACDIAG_PROTECTED_LABELS"] = protectedLabels }),
            NullLogger<MacProcessController>.Instance)
        {
            ExitWait = TimeSpan.FromMilliseconds(200),
            PollDelay = TimeSpan.Zero,
            SelfPid = () => 99999,
            IsRoot = () => root,
        };

    private static DateTimeOffset StartTime => new(new DateTime(2024, 10, 1, 8, 0, 0, DateTimeKind.Local));

    [Fact]
    public async Task A_users_remote_access_agent_is_refused_by_its_pid_in_that_users_own_domain()
    {
        var mac = new Mac();
        mac.Processes[4500] = new(1, "Ss", Start, "/Applications/Tailscale.app/Contents/MacOS/IPNExtension", "IPNExtension", Uid: 501);
        mac.UserLists[501] = "4500\t0\tio.tailscale.ipn.macsys.login-item-helper\n";

        var ex = await Assert.ThrowsAsync<ProcessControlException>(() =>
            Controller(mac).ControlAsync(4500, "IPNExtension", ProcessAction.Kill, null, CancellationToken.None));

        Assert.Contains("io.tailscale.", ex.Message, StringComparison.Ordinal);
        Assert.Contains("uid 501", ex.Message, StringComparison.Ordinal);
        Assert.Empty(mac.Signals);
    }

    [Fact]
    public async Task The_users_list_is_read_by_launchctl_running_as_that_user_not_as_root()
    {
        // As root, asuser changes the bootstrap but not the credentials, and launchctl may still answer for the
        // system domain; run as the user it lists the user's own.
        var mac = new Mac();
        mac.Processes[4600] = new(1, "S", Start, "/usr/local/bin/tool", "tool", Uid: 501);
        mac.UserLists[501] = "4600\t0\tcom.example.tool\n";
        var commands = mac.Commands;

        await new MacProcessController(commands, MacDiagOptions.FromEnvironment(new Hashtable()), NullLogger<MacProcessController>.Instance)
        {
            ExitWait = TimeSpan.FromMilliseconds(200), PollDelay = TimeSpan.Zero, SelfPid = () => 99999, IsRoot = () => true,
        }.ControlAsync(4600, "tool", ProcessAction.Terminate, null, CancellationToken.None);

        Assert.Contains(commands.Calls, c => c.Program == "launchctl" && c.Arguments.SequenceEqual(["asuser", "501", "sudo", "-n", "-u", "#501", "launchctl", "list"]));
    }

    [Fact]
    public async Task An_empty_list_for_the_users_domain_fails_closed_because_a_session_always_has_jobs()
    {
        var mac = new Mac();
        mac.Processes[4600] = new(1, "S", Start, "/usr/local/bin/tool", "tool", Uid: 501);
        mac.UserLists[501] = "";

        await Assert.ThrowsAsync<ProcessControlException>(() =>
            Controller(mac).ControlAsync(4600, "tool", ProcessAction.Terminate, null, CancellationToken.None));
        Assert.Empty(mac.Signals);
    }

    [Fact]
    public async Task A_users_list_that_is_the_system_list_again_fails_closed_because_the_wrong_domain_answered()
    {
        var mac = new Mac();
        mac.Processes[4600] = new(1, "S", Start, "/usr/local/bin/tool", "tool", Uid: 501);
        mac.UserLists[501] = string.Join('\n', Fixture(Unverified, "launchctl-list").Split('\n').Where(l => !l.StartsWith("PID", StringComparison.Ordinal)));

        var ex = await Assert.ThrowsAsync<ProcessControlException>(() =>
            Controller(mac).ControlAsync(4600, "tool", ProcessAction.Terminate, null, CancellationToken.None));

        Assert.Contains("system", ex.Message, StringComparison.Ordinal);
        Assert.Empty(mac.Signals);
    }

    [Fact]
    public async Task The_screen_sharing_agent_in_a_users_domain_stays_protected_as_the_operator_may_be_connected_through_it()
    {
        var mac = new Mac();
        mac.Processes[4900] = new(1, "S", Start, "/System/Library/CoreServices/RemoteManagement/ScreensharingAgent.bundle/Contents/MacOS/ScreensharingAgent", "ScreensharingAgent", Uid: 501);
        mac.UserLists[501] = "4900\t0\tcom.apple.screensharing.agent\n4600\t0\tcom.apple.Finder\n";

        await Assert.ThrowsAsync<ProcessControlException>(() =>
            Controller(mac).ControlAsync(4900, "ScreensharingAgent", ProcessAction.Kill, null, CancellationToken.None));
        Assert.Empty(mac.Signals);
    }

    [Theory]
    [InlineData("-2")]
    [InlineData("4294967294")]
    public async Task A_process_owned_by_nobody_is_a_system_account_with_no_user_domain(string uid)
    {
        var mac = new Mac { UidText = uid };
        mac.Processes[4800] = new(1, "S", Start, "/usr/local/bin/worker", "worker", Uid: -2);

        await Controller(mac).ControlAsync(4800, "worker", ProcessAction.Terminate, null, CancellationToken.None);

        Assert.Empty(mac.AsUser);
        Assert.Equal(["TERM 4800"], mac.Signals);
    }

    [Fact]
    public async Task Apples_own_agents_in_a_users_domain_may_be_restarted_as_launchd_relaunches_them()
    {
        var mac = new Mac();
        mac.Processes[4600] = new(1, "S", Start, "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", "Finder", Uid: 501);
        mac.UserLists[501] = "4600\t0\tcom.apple.Finder\n";

        await Controller(mac).ControlAsync(4600, "Finder", ProcessAction.Terminate, null, CancellationToken.None);

        Assert.Equal(["TERM 4600"], mac.Signals);
    }

    [Fact]
    public async Task A_users_domain_that_cannot_be_listed_fails_closed_except_for_resume()
    {
        var mac = new Mac();
        mac.Processes[4700] = new(1, "T", Start, "/usr/local/bin/tool", "tool", Uid: 502);

        await Assert.ThrowsAsync<ProcessControlException>(() =>
            Controller(mac).ControlAsync(4700, "tool", ProcessAction.Terminate, null, CancellationToken.None));
        await Controller(mac).ControlAsync(4700, "tool", ProcessAction.Resume, null, CancellationToken.None);

        Assert.Equal(["CONT 4700"], mac.Signals);
    }

    [Fact]
    public async Task A_system_accounts_process_has_no_user_domain_to_look_in()
    {
        var mac = new Mac();
        mac.Processes[4800] = new(1, "S", Start, "/usr/sbin/httpd", "/usr/sbin/httpd -D FOREGROUND", Uid: 70);

        await Controller(mac).ControlAsync(4800, "httpd", ProcessAction.Terminate, null, CancellationToken.None);

        Assert.Empty(mac.AsUser);
        Assert.Equal(["TERM 4800"], mac.Signals);
    }

    [Fact]
    public async Task A_server_that_is_not_root_reads_its_own_users_domain_where_apples_agents_are_not_protected()
    {
        var mac = new Mac();
        mac.Processes[88] = mac.Processes[88] with { Comm = "/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock", Args = "Dock", Uid = 501 };

        // launchctl list's fixture names PID 88 com.apple.WindowServer; as the user's own list, an Apple label is no refusal.
        await Controller(mac, root: false).ControlAsync(88, "Dock", ProcessAction.Terminate, null, CancellationToken.None);

        Assert.Empty(mac.AsUser);
        Assert.Equal(["TERM 88"], mac.Signals);
    }

    [Fact]
    public async Task A_matching_process_is_terminated_and_the_result_states_the_window_macos_leaves()
    {
        var mac = new Mac();

        var result = await Controller(mac).ControlAsync(640, "sleep", ProcessAction.Terminate, StartTime, CancellationToken.None);

        Assert.Equal(["TERM 640"], mac.Signals);
        Assert.Contains("Exited", result.Detail, StringComparison.Ordinal);
        Assert.Contains("no pidfd", result.Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("nginx")]
    [InlineData("/usr/bin/sleep")]
    [InlineData("Sleep")]
    public async Task A_name_that_is_not_the_process_is_refused_and_nothing_is_sent(string expected)
    {
        var mac = new Mac();

        var ex = await Assert.ThrowsAsync<ProcessControlException>(() =>
            Controller(mac).ControlAsync(640, expected, ProcessAction.Kill, null, CancellationToken.None));

        Assert.Contains("/bin/sleep", ex.Message, StringComparison.Ordinal);
        Assert.Empty(mac.Signals);
    }

    [Fact]
    public async Task The_main_process_of_a_protected_job_is_refused_and_may_still_be_resumed()
    {
        // Review Focus 2: launchctl list gives 777 as com.openssh.sshd's PID. sshd rewrites its argv, so comm decides.
        var mac = new Mac();

        await Assert.ThrowsAsync<ProcessControlException>(() =>
            Controller(mac).ControlAsync(777, "sshd", ProcessAction.Terminate, null, CancellationToken.None));
        await Controller(mac).ControlAsync(777, "sshd", ProcessAction.Resume, null, CancellationToken.None);

        Assert.Equal(["CONT 777"], mac.Signals);
    }

    [Fact]
    public async Task A_process_with_an_ordinary_name_is_refused_when_it_is_a_protected_jobs_main_pid()
    {
        // Review Focus 2, by PID alone: webd is protected by nothing but launchctl list naming it com.example.web.
        var mac = new Mac();

        await Controller(mac).ControlAsync(1234, "webd", ProcessAction.Suspend, null, CancellationToken.None);
        var ex = await Assert.ThrowsAsync<ProcessControlException>(() =>
            Controller(new Mac(), protectedLabels: "com.example.web").ControlAsync(1234, "webd", ProcessAction.Kill, null, CancellationToken.None));

        Assert.Contains("com.example.web", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_argv_that_names_a_protected_daemon_refuses_too()
    {
        // comm may follow argv[0] on macOS; refusing on either can only refuse more.
        var mac = new Mac();

        await Assert.ThrowsAsync<ProcessControlException>(() =>
            Controller(mac).ControlAsync(900, "renamed", ProcessAction.Kill, null, CancellationToken.None));
        Assert.Empty(mac.Signals);
    }

    [Fact]
    public async Task A_job_list_with_no_jobs_in_it_is_treated_as_unreadable()
    {
        var mac = new Mac { ListEmpty = true };

        await Assert.ThrowsAsync<ProcessControlException>(() =>
            Controller(mac).ControlAsync(640, "sleep", ProcessAction.Kill, null, CancellationToken.None));
        Assert.Empty(mac.Signals);
    }

    [Fact]
    public async Task A_process_protected_by_name_is_refused()
    {
        var mac = new Mac();

        var ex = await Assert.ThrowsAsync<ProcessControlException>(() =>
            Controller(mac).ControlAsync(88, "WindowServer", ProcessAction.Suspend, null, CancellationToken.None));

        Assert.Contains("WindowServer", ex.Message, StringComparison.Ordinal);
        Assert.Empty(mac.Signals);
    }

    [Fact]
    public async Task When_the_protected_job_list_cannot_be_read_everything_but_resume_is_refused()
    {
        var mac = new Mac { ListFails = true };

        await Assert.ThrowsAsync<ProcessControlException>(() =>
            Controller(mac).ControlAsync(640, "sleep", ProcessAction.Kill, null, CancellationToken.None));
        Assert.Empty(mac.Signals);
    }

    [Fact]
    public async Task A_pid_that_changes_hands_while_it_is_checked_gets_no_signal()
    {
        // Review Focus 3.
        var mac = new Mac { ChangesHandsOnReread = true };

        var ex = await Assert.ThrowsAsync<ProcessControlException>(() =>
            Controller(mac).ControlAsync(640, "sleep", ProcessAction.Kill, null, CancellationToken.None));

        Assert.Contains("changed hands", ex.Message, StringComparison.Ordinal);
        Assert.Empty(mac.Signals);
    }

    [Fact]
    public async Task A_start_time_other_than_the_one_expected_is_refused()
    {
        var mac = new Mac();

        await Assert.ThrowsAsync<ProcessControlException>(() =>
            Controller(mac).ControlAsync(640, "sleep", ProcessAction.Kill, StartTime.AddMinutes(-5), CancellationToken.None));
        Assert.Empty(mac.Signals);
    }

    [Fact]
    public async Task Terminating_a_stopped_process_also_lets_it_run_so_it_can_exit()
    {
        var mac = new Mac();

        await Controller(mac).ControlAsync(641, "sleep", ProcessAction.Terminate, null, CancellationToken.None);

        Assert.Equal(["TERM 641", "CONT 641"], mac.Signals);
    }

    [Theory]
    [InlineData(642, "zombie")]
    [InlineData(1, "PID 1")]
    [InlineData(99999, "this server")]
    [InlineData(4242, "No process with PID 4242")]
    public async Task Zombies_pid_1_this_server_and_missing_pids_are_refused(int pid, string reason)
    {
        var mac = new Mac();

        var ex = await Assert.ThrowsAsync<ProcessControlException>(() =>
            Controller(mac).ControlAsync(pid, "sleep", ProcessAction.Kill, null, CancellationToken.None));

        Assert.Contains(reason, ex.Message, StringComparison.Ordinal);
        Assert.Empty(mac.Signals);
    }

    [Fact]
    public async Task A_pid_of_zero_or_less_is_refused_before_anything_runs()
    {
        var mac = new Mac();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            Controller(mac).ControlAsync(0, "sleep", ProcessAction.Kill, null, CancellationToken.None));
    }
}
