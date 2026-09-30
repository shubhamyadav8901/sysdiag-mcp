using LinuxDiag.Mcp.Diagnostics.Containers;
using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Tools;

namespace LinuxDiag.Mcp.Tests;

public sealed class ProcessListTests
{
    private static readonly string Id = new('a', 64);
    private static readonly ContainerCatalog NoContainers = new([], []);

    private static ProcessRecord Record(
        int pid, string name, string? cmdline = null, bool denied = false, ContainerReference? container = null,
        int? innermost = null, int ppid = 1) =>
        new(pid, ppid, name, "S", false, 100, DateTimeOffset.UnixEpoch.AddDays(1), 4096, 2, 1000, null,
            cmdline, denied, "/", container, innermost, "net:[1]", "mnt:[1]");

    [Fact]
    public void A_proc_mounted_to_hide_other_users_is_detected_and_said()
    {
        // Final review of plan 2: under hidepid=invisible other users' processes are simply absent, and nothing
        // counted them as unreadable -- the list looked complete.
        static IReadOnlyList<MountInfoEntry> Proc(string options) =>
            MountInfo.Parse($"22 1 0:5 / /proc rw,nosuid shared:1 - proc proc {options}\n");

        Assert.True(ProcMount.HidesOtherUsers(Proc("rw,hidepid=invisible")));
        Assert.True(ProcMount.HidesOtherUsers(Proc("rw,hidepid=2")));
        Assert.True(ProcMount.HidesOtherUsers(Proc("rw,hidepid=ptraceable")));
        Assert.False(ProcMount.HidesOtherUsers(Proc("rw,hidepid=noaccess")));
        Assert.False(ProcMount.HidesOtherUsers(Proc("rw")));

        var result = ProcessTools.Build(new ProcessTable([], 0, 0, OthersHidden: true), new([], []), null, null, 100);

        Assert.Contains("hidepid", result.Limitation, StringComparison.Ordinal);
    }

    [Fact]
    public void One_process_that_fails_with_an_unexpected_io_error_is_counted_not_fatal()
    {
        // Final review of plan 2: a single EIO from one live process failed the whole walk.
        var stat = ProcParserTests.Fixture(ProcParserTests.Distros().First(), "pid-stat")!;
        RawProcess? Collect(int pid) => pid == 2
            ? throw new IOException("Input/output error")
            : new RawProcess(pid, stat, null, null, null, null, null, null, false);

        var table = LinuxProcessTable.Walk([1, 2, 3], Collect, DateTimeOffset.UnixEpoch, CancellationToken.None);

        Assert.Equal(2, table.Processes.Count);
        Assert.Equal(1, table.Unreadable);
    }

    [Fact]
    public void A_filter_matches_name_command_line_or_container_name_and_rows_are_ordered_by_name_then_pid()
    {
        var catalog = new ContainerCatalog([new ContainerInfo("docker", Id, "shop-web", "nginx", "running", 30, [30], null, null, false)], []);
        var table = new ProcessTable(
        [
            Record(20, "python3", "python3 /srv/shop/app.py"),
            Record(30, "nginx", "nginx: master", container: new("docker", Id), innermost: 1),
            Record(10, "bash", "bash"),
            Record(11, "python3", "python3 other.py"),
        ], 0);

        var result = ProcessTools.Build(table, catalog, "shop", null, 100);

        Assert.Equal([30, 20], result.Processes.Select(p => p.ProcessId));
        Assert.Equal(new ProcessContainer("docker", Id, "shop-web", "nginx", 1), result.Processes[0].Container);
        Assert.Equal(2, result.TotalMatched);
        Assert.Equal([11, 20], ProcessTools.Build(table, catalog, "python3", null, 100).Processes.Select(p => p.ProcessId));
    }

    [Fact]
    public void Pid_1s_parent_0_is_reported_as_no_parent()
    {
        var result = ProcessTools.Build(new ProcessTable([Record(1, "systemd", "/sbin/init", ppid: 0)], 0), NoContainers, null, 1, 100);

        Assert.Null(Assert.Single(result.Processes).ParentProcessId);
    }

    [Fact]
    public void An_unreadable_command_line_is_counted_and_explained_and_a_kernel_threads_absence_is_not()
    {
        var result = ProcessTools.Build(
            new ProcessTable([Record(5, "secret", denied: true), Record(6, "kworker/0:1")], 3), NoContainers, null, null, 100);

        Assert.Equal(1, result.CommandLinesRedacted);
        Assert.Contains("could not access the process", result.Summary, StringComparison.Ordinal);
        Assert.Contains("3 processes could not be read", result.Limitation, StringComparison.Ordinal);
    }

    [Fact]
    public void Processes_whose_executable_and_namespaces_were_denied_are_counted_in_the_limitation()
    {
        var result = ProcessTools.Build(new ProcessTable([Record(5, "a")], 0, PartlyUnreadable: 7), NoContainers, null, null, 100);

        Assert.Contains("7 processes owned by other users", result.Limitation, StringComparison.Ordinal);
    }

    [Fact]
    public void A_container_runtime_that_could_not_be_asked_is_in_the_limitation()
    {
        var result = ProcessTools.Build(new ProcessTable([Record(5, "a")], 0), new ContainerCatalog([], ["Docker did not answer."]), null, null, 100);

        Assert.Contains("Docker did not answer.", result.Limitation, StringComparison.Ordinal);
        Assert.StartsWith("WARNING: ", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Rows_past_the_cap_are_truncated_and_prose_past_the_render_limit_says_so()
    {
        // Review Focus 5.
        var table = new ProcessTable(Enumerable.Range(1, 500).Select(i => Record(i, "worker", "worker")).ToList(), 0);

        var capped = ProcessTools.Build(table, NoContainers, null, null, 300);
        var full = ProcessTools.Build(table, NoContainers, null, null, 1000);

        Assert.Equal(300, capped.Processes.Count);
        Assert.True(capped.Truncated);
        Assert.Contains("LINUXDIAG_MAX_RESULTS", capped.Summary, StringComparison.Ordinal);
        Assert.Contains("Summary lists the first 200 of 500", full.Summary, StringComparison.Ordinal);
        Assert.False(full.Truncated);
    }

    [Fact]
    public void No_match_says_what_was_asked()
    {
        var result = ProcessTools.Build(new ProcessTable([Record(5, "a")], 0), NoContainers, "zzz", null, 100);

        Assert.Empty(result.Processes);
        Assert.Contains("No process matched 'zzz'.", result.Summary, StringComparison.Ordinal);
    }

    [DockerFact]
    public async Task A_container_process_is_tagged_with_its_container_and_its_pid_inside()
    {
        var name = $"ld-plist-{Guid.NewGuid():N}"[..20];
        var id = ContainerTests.Docker($"run -d --name {name} busybox sleep 120");
        try
        {
            var tools = new ProcessTools(new LinuxProcessTable(), new LinuxContainerInspector(),
                Configuration.LinuxDiagOptions.FromEnvironment(new System.Collections.Hashtable()));

            var result = await tools.ProcessList(nameFilter: name);

            var process = Assert.Single(result.Processes, p => p.Container?.Id == id);
            Assert.Equal(name, process.Container!.Name);
            Assert.Equal(1, process.Container.ProcessIdInContainer);
            Assert.Equal("sleep 120", process.CommandLine);
        }
        finally
        {
            ContainerTests.Docker($"rm -f {id}");
        }
    }
}
