using System.Diagnostics;
using LinuxDiag.Mcp.Diagnostics.Control;
using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Linux.Native;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Linux.Proc;
using LinuxDiag.Mcp.Tools;
using Microsoft.Extensions.Logging.Abstractions;

namespace LinuxDiag.Mcp.Tests;

public sealed class ControlTests
{
    private static LinuxProcessController Controller(TimeSpan? wait = null) =>
        new(NullLogger<LinuxProcessController>.Instance) { ExitWait = wait ?? TimeSpan.FromSeconds(10) };

    [Theory]
    [InlineData("terminate", ProcessAction.Terminate)]
    [InlineData(" End ", ProcessAction.Terminate)]
    [InlineData("kill", ProcessAction.Kill)]
    [InlineData("suspend", ProcessAction.Suspend)]
    [InlineData("freeze", ProcessAction.Suspend)]
    [InlineData("pause", ProcessAction.Suspend)]
    [InlineData("resume", ProcessAction.Resume)]
    [InlineData("unfreeze", ProcessAction.Resume)]
    [InlineData("continue", ProcessAction.Resume)]
    public void Actions_keep_windiags_names_and_aliases(string text, ProcessAction action)
    {
        Assert.Equal(action, ControlTools.ParseAction(text));
    }

    [Fact]
    public void An_unknown_action_names_the_four_that_exist()
    {
        var ex = Assert.Throws<ArgumentException>(() => ControlTools.ParseAction("nuke"));

        Assert.Contains("'terminate', 'kill', 'suspend' or 'resume'", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("sleep", true)]
    [InlineData("SLEEP", true)]
    [InlineData("/usr/bin/sleep", true)]
    [InlineData("systemd-journald", true)] // comm is cut to 15 bytes: "systemd-journal"
    [InlineData("sleepy", false)]
    [InlineData("bash", false)]
    public void An_expected_name_matches_comm_the_executable_or_argv0(string expected, bool matches)
    {
        Assert.Equal(matches, LinuxProcessController.NamesMatch(["sleep", "sleep", "systemd-journal"], expected));
    }

    [Fact]
    public void Pid_1_this_server_and_a_non_positive_pid_are_refused_before_anything_is_opened()
    {
        Assert.Contains("Refusing to signal PID 1", Assert.Throws<ProcessControlException>(() =>
            Controller().Control(1, "systemd", ProcessAction.Terminate, CancellationToken.None)).Message, StringComparison.Ordinal);
        Assert.Contains("own process", Assert.Throws<ProcessControlException>(() =>
            Controller().Control(Environment.ProcessId, "dotnet", ProcessAction.Kill, CancellationToken.None)).Message, StringComparison.Ordinal);
        Assert.Throws<ArgumentOutOfRangeException>(() => Controller().Control(0, "x", ProcessAction.Suspend, CancellationToken.None));
        Assert.Throws<ArgumentException>(() => Controller().Control(99, " ", ProcessAction.Suspend, CancellationToken.None));
        Assert.Throws<ArgumentException>(() => Controller().Control(99, "/", ProcessAction.Suspend, CancellationToken.None));
    }

    [LinuxFact]
    public void A_signal_through_a_pidfd_to_a_reaped_process_fails_instead_of_reaching_a_newcomer()
    {
        // The invariant the whole tool rests on: once the pidfd is open, the PID can be reused and the
        // signal still cannot land on the newcomer.
        using var child = Process.Start("sleep", "60");
        using var pidfd = LibC.OpenPidFd(child.Id);
        child.Kill();
        child.WaitForExit();

        var ex = Assert.Throws<ErrnoException>(() => LibC.SendSignal(pidfd, 0));

        Assert.Equal(ErrnoException.ESRCH, ex.Errno);
    }

    [LinuxFact]
    public void A_start_time_that_does_not_match_is_refused_before_any_signal_and_a_matching_one_proceeds()
    {
        // The pidfd covers only the call; a PID reused before it, by a process with the same name, is caught
        // by the start time process_list reported.
        using var child = Process.Start("sleep", "60");
        try
        {
            var ex = Assert.Throws<ProcessControlException>(() => Controller().Control(
                child.Id, "sleep", ProcessAction.Kill, CancellationToken.None, DateTimeOffset.UnixEpoch));
            Assert.Contains("started at", ex.Message, StringComparison.Ordinal);
            Assert.False(child.WaitForExit(500));

            var started = new LinuxProcessTable().Read(CancellationToken.None).Processes.Single(p => p.ProcessId == child.Id).StartTime;
            var suspended = Controller().Control(child.Id, "sleep", ProcessAction.Suspend, CancellationToken.None, started);
            Assert.Equal(ProcessAction.Suspend, suspended.Action);
            Controller().Control(child.Id, "sleep", ProcessAction.Resume, CancellationToken.None);
        }
        finally
        {
            child.Kill();
        }
    }

    [LinuxFact]
    public void A_call_cancelled_before_it_signals_signals_nothing()
    {
        using var child = Process.Start("sleep", "60");
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        try
        {
            Assert.ThrowsAny<OperationCanceledException>(() =>
                Controller().Control(child.Id, "sleep", ProcessAction.Kill, cancelled.Token));
            Assert.False(child.WaitForExit(500));
        }
        finally
        {
            child.Kill();
        }
    }

    [LinuxFact]
    public void A_wait_cancelled_after_the_signal_says_the_signal_was_sent()
    {
        // Reporting only "cancelled" would hide that a root SIGTERM has already been delivered.
        using var child = Process.Start("sh", ["-c", "trap '' TERM; while :; do sleep 1; done"]);
        try
        {
            WaitUntilIgnoring(child.Id, signal: 15);
            using var soon = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));

            var ex = Assert.Throws<ProcessControlException>(() =>
                Controller().Control(child.Id, "sh", ProcessAction.Terminate, soon.Token));

            Assert.Contains("SIGTERM was sent", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            child.Kill();
        }
    }

    [LinuxFact]
    public void Suspend_resume_and_terminate_a_child_by_signal()
    {
        using var child = Process.Start("sleep", "60");
        try
        {
            Assert.StartsWith("Stopped", Controller().Control(child.Id, "sleep", ProcessAction.Suspend, CancellationToken.None).Detail, StringComparison.Ordinal);
            WaitForState(child.Id, "T");

            Controller().Control(child.Id, "sleep", ProcessAction.Resume, CancellationToken.None);
            WaitForState(child.Id, "S");

            var terminated = Controller().Control(child.Id, "sleep", ProcessAction.Terminate, CancellationToken.None);
            Assert.StartsWith("Exited", terminated.Detail, StringComparison.Ordinal);
            Assert.Equal(ProcessAction.Terminate, terminated.Action);
            Assert.NotNull(terminated.StartTime);
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill();
            }
        }
    }

    [LinuxFact]
    public void A_suspended_process_is_continued_after_sigterm_so_terminate_ends_it()
    {
        using var child = Process.Start("sleep", "60");
        try
        {
            Controller().Control(child.Id, "sleep", ProcessAction.Suspend, CancellationToken.None);
            WaitForState(child.Id, "T");

            var watch = Stopwatch.StartNew();
            var terminated = Controller().Control(child.Id, "sleep", ProcessAction.Terminate, CancellationToken.None);

            Assert.StartsWith("Exited", terminated.Detail, StringComparison.Ordinal);
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"took {watch.Elapsed}");
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill();
            }
        }
    }

    [LinuxFact]
    public void A_wrong_expected_name_is_refused_and_the_process_is_untouched()
    {
        using var child = Process.Start("sleep", "60");
        try
        {
            var ex = Assert.Throws<ProcessControlException>(() =>
                Controller().Control(child.Id, "nginx", ProcessAction.Kill, CancellationToken.None));

            Assert.Contains("is 'sleep', not 'nginx'", ex.Message, StringComparison.Ordinal);
            Assert.False(child.WaitForExit(1000)); // HasExited alone passes before a SIGKILL is reaped
        }
        finally
        {
            child.Kill();
        }
    }

    [LinuxFact]
    public void A_process_ignoring_sigterm_is_reported_as_still_running_and_kill_ends_it()
    {
        using var child = Process.Start("sh", ["-c", "trap '' TERM; while :; do sleep 1; done"]);
        try
        {
            WaitUntilIgnoring(child.Id, signal: 15); // the trap must be in place before SIGTERM arrives
            var terminated = Controller(TimeSpan.FromMilliseconds(500)).Control(child.Id, "sh", ProcessAction.Terminate, CancellationToken.None);
            Assert.Contains("has not exited", terminated.Detail, StringComparison.Ordinal);

            var killed = Controller().Control(child.Id, "sh", ProcessAction.Kill, CancellationToken.None);
            Assert.StartsWith("Exited", killed.Detail, StringComparison.Ordinal);
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill();
            }
        }
    }

    [LinuxFact]
    public void A_thread_id_and_a_pid_that_is_not_running_are_each_explained()
    {
        var tid = Directory.EnumerateDirectories($"/proc/{Environment.ProcessId}/task")
            .Select(d => int.Parse(Path.GetFileName(d), System.Globalization.CultureInfo.InvariantCulture))
            .First(t => t != Environment.ProcessId);

        Assert.Contains("is a thread", Assert.Throws<ProcessControlException>(() =>
            Controller().Control(tid, "dotnet", ProcessAction.Suspend, CancellationToken.None)).Message, StringComparison.Ordinal);
        Assert.Contains("No process with PID", Assert.Throws<ProcessControlException>(() =>
            Controller().Control(int.MaxValue, "x", ProcessAction.Suspend, CancellationToken.None)).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_read_only_server_does_not_register_process_control()
    {
        using var readOnly = ToolRegistrationTests.Provider(ToolRegistrationTests.Options(readOnly: true));
        using var writable = ToolRegistrationTests.Provider(ToolRegistrationTests.Options());

        Assert.DoesNotContain(ToolNames(readOnly), n => n == "process_control");
        Assert.Contains(ToolNames(writable), n => n == "process_control");
    }

    private static IEnumerable<string> ToolNames(IServiceProvider provider) =>
        Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions
            .GetServices<ModelContextProtocol.Server.McpServerTool>(provider).Select(t => t.ProtocolTool.Name);

    private static void WaitUntilIgnoring(int pid, int signal)
    {
        var watch = Stopwatch.StartNew();
        while (true)
        {
            var line = ProcFiles.ReadProcess(pid, "status")!.Split('\n').First(l => l.StartsWith("SigIgn:", StringComparison.Ordinal));
            var mask = ulong.Parse(line[7..].Trim(), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
            if ((mask & (1UL << (signal - 1))) != 0)
            {
                return;
            }

            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"PID {pid} never ignored signal {signal}");
            Thread.Sleep(20);
        }
    }

    private static void WaitForState(int pid, string state)
    {
        var watch = Stopwatch.StartNew();
        while (ProcStat.Parse(ProcFiles.ReadProcess(pid, "stat")!).State != state)
        {
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"PID {pid} never reached state {state}");
            Thread.Sleep(20);
        }
    }
}
