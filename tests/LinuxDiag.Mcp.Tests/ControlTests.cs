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
    [InlineData("systemd-journal", true)]                    // comm
    [InlineData("systemd-journald", true)]                   // the executable's name, and comm's 15-byte prefix
    [InlineData("/usr/lib/systemd/systemd-journald", true)]  // a path is compared whole
    [InlineData("/tmp/systemd-journald", false)]             // not by its last part
    [InlineData("SYSTEMD-JOURNALD", false)]                  // names are case-sensitive on Linux
    [InlineData("journald", false)]
    public void An_expected_name_matches_comm_the_executable_or_argv0_exactly(string expected, bool matches)
    {
        Assert.Equal(matches, LinuxProcessController.NamesMatch(
            "systemd-journal", "/usr/lib/systemd/systemd-journald", "/usr/lib/systemd/systemd-journald", expected));
    }

    [Fact]
    public void A_path_matches_a_replaced_binary_a_symlink_and_a_script()
    {
        // Final review: after an upgrade the exe link ends " (deleted)" and nginx rewrites argv0; merged-usr and
        // alternatives reach the binary through a link; a script's exe is its interpreter and its path is argv[1].
        Assert.True(LinuxProcessController.NamesMatch(
            "nginx", "/usr/sbin/nginx (deleted)", "nginx: master process /usr/sbin/nginx", "/usr/sbin/nginx"));
        Assert.True(LinuxProcessController.NamesMatch(
            "python3", "/usr/bin/python3.12", "python3", "/usr/bin/python3", expectedResolved: "/usr/bin/python3.12"));
        Assert.True(LinuxProcessController.NamesMatch(
            "job.sh", "/usr/bin/bash", "/bin/bash", "/usr/local/bin/job.sh", argv1: "/usr/local/bin/job.sh"));
        Assert.False(LinuxProcessController.NamesMatch(
            "bash", "/usr/bin/bash", "/bin/bash", "/usr/local/bin/job.sh", argv1: "/usr/local/bin/job.sh"));
    }

    [Fact]
    public void Only_comm_is_matched_on_its_truncated_prefix()
    {
        // The kernel cuts comm to 15 bytes; an executable name or argv[0] is never cut, so no prefix rule applies.
        Assert.True(LinuxProcessController.NamesMatch("averyveryverylo", null, null, "averyveryverylongname"));
        Assert.False(LinuxProcessController.NamesMatch("x", "/opt/averyveryverylo", null, "averyveryverylongname"));
    }

    [Theory]
    [InlineData("/system.slice/dbus-broker.service", "dbus-broker", "/usr/bin/dbus-broker", 4242, true)]  // the launcher's child
    [InlineData("/system.slice/ssh.service", "sshd", "/usr/sbin/sshd", 1, true)]                         // the listener
    [InlineData("/system.slice/systemd-journald.service", "systemd-journal", "/usr/lib/systemd/systemd-journald", 1, true)]
    [InlineData("/system.slice/tailscaled.service", "tailscaled", "/usr/sbin/tailscaled", 1, true)]
    [InlineData("/user.slice/user-1000.slice/session-3.scope", "sshd", "/usr/sbin/sshd", 1, false)]     // an orphan named sshd
    [InlineData("/system.slice/system-sshd.slice/sshd@1-10.0.0.1:22-10.0.0.2:5000.service", "sshd", "/usr/sbin/sshd", 1, false)]
    [InlineData("/system.slice/nginx.service", "nginx", "/usr/sbin/nginx", 1, false)]
    [InlineData("/", "sshd", "/usr/sbin/sshd", 1, true)]                                                  // no systemd: by name
    [InlineData("/", "sshd", "/usr/sbin/sshd", 4242, false)]
    public void A_process_in_a_unit_the_machine_needs_is_protected_and_nothing_else_is(
        string cgroup, string comm, string exe, int parent, bool isProtected)
    {
        // Final review: dbus-broker runs as the child of dbus-broker-launch, so "parent is PID 1" left the
        // system bus killable; and any orphan named sshd was unkillable. The unit decides, as service_control's does.
        Assert.Equal(isProtected, LinuxProcessController.IsProtected(cgroup, comm, exe, parent));
    }

    [Theory]
    [InlineData("t", ProcessAction.Terminate, "under a debugger")]
    [InlineData("T", ProcessAction.Terminate, "was suspended, so it was continued")]
    [InlineData("S", ProcessAction.Terminate, null)]
    public void The_result_says_when_the_processs_stopped_state_changes_what_the_signal_does(string state, ProcessAction action, string? note)
    {
        var text = LinuxProcessController.StateNote(state, action);

        if (note is null)
        {
            Assert.Null(text);
        }
        else
        {
            Assert.Contains(note, text, StringComparison.Ordinal);
        }
    }

    [LinuxFact]
    public void A_zombie_is_refused_because_no_signal_reaches_it()
    {
        // bash starts a child and then becomes sleep, which never reaps it: the child stays a zombie.
        using var parent = Process.Start(new ProcessStartInfo("bash", ["-c", "sleep 0 & exec sleep 30"]))!;
        try
        {
            var children = $"/proc/{parent.Id}/task/{parent.Id}/children";
            int? zombie = null;
            var watch = Stopwatch.StartNew();
            while (zombie is null && watch.Elapsed < TimeSpan.FromSeconds(5))
            {
                zombie = File.ReadAllText(children).Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .Select(int.Parse)
                    .Cast<int?>()
                    .FirstOrDefault(pid => File.ReadAllText($"/proc/{pid}/stat").Split(") ")[1].StartsWith('Z'));
                Thread.Sleep(50);
            }

            Assert.NotNull(zombie);
            var ex = Assert.Throws<ProcessControlException>(() =>
                Controller().Control(zombie!.Value, "sleep", ProcessAction.Terminate, CancellationToken.None));

            Assert.Contains("zombie", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            parent.Kill();
        }
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

            Assert.Contains("is 'sleep' (executable /", ex.Message, StringComparison.Ordinal);
            Assert.Contains("not 'nginx'", ex.Message, StringComparison.Ordinal);
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
