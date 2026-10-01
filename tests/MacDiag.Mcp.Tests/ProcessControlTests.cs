using System.Collections;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Control;
using Microsoft.Extensions.Logging.Abstractions;
using static MacDiag.Mcp.Tests.SystemOverviewTests;

namespace MacDiag.Mcp.Tests;

public sealed class ProcessControlTests
{
    private const string Start = "Tue Oct  1 08:00:00 2024";

    private sealed record Proc(int Ppid, string Stat, string Start, string Comm, string Args);

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
        };

        public bool ChangesHandsOnReread { get; init; }

        public bool ListFails { get; init; }

        public List<string> Signals { get; } = [];

        private int _identityReads;

        public FakeCommands Commands => new((program, args) => program switch
        {
            "ps" => Ps(args),
            "kill" => Kill(args),
            "launchctl" when args[0] == "list" => ListFails ? new ExternalResult(1, "", "launchctl: timed out") : FakeCommands.Ok(Fixture(Unverified, "launchctl-list")),
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

            // The re-read just before the signal asks for pid, lstart and comm only.
            var start = columns == "pid=,lstart=,comm=" && ChangesHandsOnReread ? "Tue Oct  1 09:59:59 2024" : p.Start;
            _identityReads++;
            return columns == "pid=,lstart=,comm="
                ? FakeCommands.Ok($"  {pid} {start}     {p.Comm}\n")
                : FakeCommands.Ok($"  {pid}     {p.Ppid} {p.Stat}  {start}     {p.Comm}\n");
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

    private static MacProcessController Controller(Mac mac) =>
        new(mac.Commands, MacDiagOptions.FromEnvironment(new Hashtable()), NullLogger<MacProcessController>.Instance)
        {
            ExitWait = TimeSpan.FromMilliseconds(200),
            PollDelay = TimeSpan.Zero,
            SelfPid = () => 99999,
        };

    private static DateTimeOffset StartTime => new(new DateTime(2024, 10, 1, 8, 0, 0, DateTimeKind.Local));

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
