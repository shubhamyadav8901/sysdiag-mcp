using System.Diagnostics;
using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Linux.Proc;

namespace LinuxDiag.Mcp.Tests;

public sealed class ProcessTableTests
{
    private static readonly DateTimeOffset Boot = DateTimeOffset.FromUnixTimeSeconds(1_790_770_000);

    private static RawProcess Raw(string stat, string? status = null, string? cmdline = null, string? cgroup = null) =>
        new(ProcessId: 0, stat, status, cmdline, cgroup, ExecutablePath: "/usr/bin/sleep",
            NetworkNamespace: "net:[4026531840]", MountNamespace: "mnt:[4026532223]", CommandLineDenied: false);

    [Fact]
    public void A_record_joins_stat_status_cmdline_and_cgroup()
    {
        var record = LinuxProcessTable.Parse(
            Raw("771 (sleep) S 749 771 771 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 250 0 484 0",
                "Uid:\t0\t0\t0\t0\nNSpid:\t771\t1\n",
                "sleep\0600\0",
                "0::/system.slice/docker-5e8adee615fb5940921b8d3b75f357a0ff9d84515283e9359c02b34f44671f9e.scope\n"),
            Boot);

        Assert.Equal(771, record.ProcessId);
        Assert.Equal("sleep 600", record.CommandLine);
        Assert.Equal(Boot.AddSeconds(2.5), record.StartTime);
        Assert.Equal(484L * Environment.SystemPageSize, record.ResidentBytes);
        Assert.Equal(1, record.InnermostProcessId);
        Assert.Equal("docker", record.Container?.Runtime);
        Assert.Equal(0L, record.UserId);
    }

    [Fact]
    public void A_kernel_thread_has_no_command_line_or_executable_and_is_not_counted_as_redacted()
    {
        var record = LinuxProcessTable.Parse(
            Raw("15 (kworker/0:1) I 2 0 0 0 -1 69238880 0 0 0 0 0 0 0 0 20 0 1 0 12 0 0 0", cmdline: ""), Boot);

        Assert.True(record.KernelThread);
        Assert.Null(record.CommandLine);
        Assert.Null(record.ExecutablePath);
        Assert.False(record.CommandLineDenied);
        Assert.Equal("/", record.CgroupPath);
    }

    [LinuxFact]
    public void A_process_that_does_not_exist_reads_as_gone_not_as_an_error()
    {
        // Review Focus 1: between listing /proc and reading a file in it, the process can exit.
        Assert.False(ProcFiles.IsAlive(int.MaxValue));
        Assert.Null(ProcFiles.ReadProcess(int.MaxValue, "stat"));
        Assert.Null(ProcFiles.ReadProcessLink(int.MaxValue, "exe"));
    }

    [LinuxFact]
    public void A_real_read_error_from_a_live_process_is_not_mistaken_for_it_exiting()
    {
        // The rule is "gone means not alive any more", not "any IOException": a live process's failed read
        // must surface, or a genuine error reads as an empty answer.
        Assert.ThrowsAny<IOException>(() => ProcFiles.ReadProcess(Environment.ProcessId, "no-such-entry"));
    }

    [UnprivilegedLinuxFact]
    public void Another_users_process_is_counted_as_partly_unreadable_not_silently_blanked()
    {
        // PID 1 is root's: its exe link and namespaces are denied to this account. Blanking them silently
        // made a non-root answer look complete.
        Assert.True(LinuxProcessTable.Collect(1)!.AttributesDenied);
        Assert.True(new LinuxProcessTable().Read(CancellationToken.None).PartlyUnreadable > 0);
    }

    [LinuxFact]
    public void The_live_table_holds_this_process_with_its_real_start_time_and_command_line()
    {
        var table = new LinuxProcessTable().Read(CancellationToken.None);
        var self = Assert.Single(table.Processes, p => p.ProcessId == Environment.ProcessId);

        using var process = Process.GetCurrentProcess();
        Assert.True((self.StartTime - process.StartTime.ToUniversalTime()).Duration() < TimeSpan.FromSeconds(2),
            $"table {self.StartTime:o}, runtime {process.StartTime.ToUniversalTime():o}");
        Assert.NotNull(self.CommandLine);
        Assert.NotNull(self.NetworkNamespace);
        Assert.Contains(table.Processes, p => p.ProcessId == 1);
    }
}
