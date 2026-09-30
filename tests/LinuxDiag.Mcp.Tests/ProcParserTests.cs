using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Tests;

/// <summary>The per-process formats, against lines captured from WSL and every captured distro.</summary>
public sealed class ProcParserTests
{
    internal static IEnumerable<string> Distros() =>
        Directory.EnumerateDirectories(Path.Combine(AppContext.BaseDirectory, "Fixtures")).Select(d => Path.GetFileName(d)!);

    internal static string? Fixture(string distro, string name)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", distro, name);
        return File.Exists(path) ? File.ReadAllText(path) : null;
    }

    [Fact]
    public void A_stat_line_is_read_by_its_proc5_field_numbers()
    {
        // Captured from WSL Ubuntu: `cat /proc/self/stat`.
        var entry = ProcStat.Parse(
            "887 (cat) R 613 613 613 34816 613 4194304 128 0 0 0 0 0 0 0 20 0 1 0 19578 3346432 396 " +
            "18446744073709551615 97731328241664 97731328259249 140734329159728 0 0 0 0 0 0 0 0 0 17 20 0 0 0 0 0");

        Assert.Equal(887, entry.ProcessId);
        Assert.Equal("cat", entry.Name);
        Assert.Equal("R", entry.State);
        Assert.Equal(613, entry.ParentProcessId);
        Assert.Equal(1, entry.ThreadCount);
        Assert.Equal(19578, entry.StartTimeTicks);
        Assert.Equal(396, entry.ResidentPages);
        Assert.False(entry.IsKernelThread);
    }

    [Fact]
    public void A_name_holding_parentheses_and_spaces_is_read_up_to_the_last_close_parenthesis()
    {
        // Captured from WSL: PID 2 is "init-systemd(Ub", truncated to 15 bytes mid-word. A split on the
        // first ')' or on spaces reads every later field one place off.
        var entry = ProcStat.Parse(
            "2 (init-systemd(Ub) S 1 0 0 0 -1 4194624 153 12637 0 866 0 1 12 24 20 0 2 0 455 3194880 484 " +
            "18446744073709551615 1 1 0 0 0 0 0 2147090174 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0");
        var spaced = ProcStat.Parse("40 (a b) c)) S 1 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 3 0 99 0 5 0");

        Assert.Equal("init-systemd(Ub", entry.Name);
        Assert.Equal(1, entry.ParentProcessId);
        Assert.Equal(455, entry.StartTimeTicks);
        Assert.Equal("a b) c)", spaced.Name);
        Assert.Equal(3, spaced.ThreadCount);
    }

    [Fact]
    public void A_kernel_thread_is_known_by_its_flag_not_by_its_parent()
    {
        // PF_KTHREAD is 0x00200000 in field 9. In WSL, PID 2 is not kthreadd, so "parent is 2" is wrong.
        var kernel = ProcStat.Parse("15 (kworker/0:1) I 2 0 0 0 -1 69238880 0 0 0 0 0 0 0 0 20 0 1 0 12 0 0 0");

        Assert.True(kernel.IsKernelThread);
    }

    [Fact]
    public void A_truncated_stat_line_is_a_format_error_naming_the_file()
    {
        var ex = Assert.Throws<FormatException>(() => ProcStat.Parse("12 (x) S 1"));

        Assert.Contains("/proc/<pid>/stat", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Status_gives_the_real_uid_and_the_pid_inside_a_container()
    {
        // Captured from a busybox container's `sleep` in WSL Ubuntu.
        var status = ProcStatus.Parse(
            "Name:\tsleep\nState:\tS (sleeping)\nTgid:\t771\nPid:\t771\nPPid:\t749\nUid:\t0\t0\t0\t0\nNSpid:\t771\t1\n");
        var host = ProcStatus.Parse("Name:\tbash\nUid:\t1000\t1000\t1000\t1000\nNSpid:\t613\n");

        Assert.Equal(0L, status.RealUserId);
        Assert.Equal(1, status.InnermostProcessId);
        Assert.Equal(1000L, host.RealUserId);
        Assert.Null(host.InnermostProcessId);
    }

    [Theory]
    [InlineData("0::/system.slice/docker-5e8adee615fb5940921b8d3b75f357a0ff9d84515283e9359c02b34f44671f9e.scope\n",
        "docker", "5e8adee615fb5940921b8d3b75f357a0ff9d84515283e9359c02b34f44671f9e")]
    [InlineData("0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice/cri-containerd-" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope\n",
        "containerd", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("0::/machine.slice/libpod-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.scope\n",
        "podman", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]
    [InlineData("0::/system.slice/crio-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.scope\n",
        "cri-o", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")]
    [InlineData("12:memory:/docker/dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\n" +
        "11:cpu,cpuacct:/docker/dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\n",
        "docker", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")]
    [InlineData("4:pids:/kubepods/burstable/pod1/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n",
        "kubernetes", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")]
    // Podman puts a container's processes one level below its scope.
    [InlineData("0::/machine.slice/libpod-9999999999999999999999999999999999999999999999999999999999999999.scope/container\n",
        "podman", "9999999999999999999999999999999999999999999999999999999999999999")]
    // A hybrid host: the unified line names the shim's service, the v1 controllers carry Docker's cgroupfs path.
    [InlineData("12:memory:/docker/8888888888888888888888888888888888888888888888888888888888888888\n0::/system.slice/containerd.service\n",
        "docker", "8888888888888888888888888888888888888888888888888888888888888888")]
    public void A_container_is_recognised_from_its_cgroup_path(string cgroup, string runtime, string id)
    {
        var container = CgroupPath.ContainerOf(cgroup);

        Assert.Equal(new ContainerReference(runtime, id), container);
    }

    [Theory]
    [InlineData("0::/init.scope\n")]
    [InlineData("0::/user.slice/user-1000.slice/session-1.scope\n")]
    [InlineData("0::/system.slice/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n")]
    public void A_cgroup_no_runtime_claims_is_no_container_and_keeps_its_raw_path(string cgroup)
    {
        // Spec L3: a cgroup that matches no runtime is reported as its raw path, never dropped.
        var path = CgroupPath.Parse(cgroup);

        Assert.Null(CgroupPath.Container(path));
        Assert.Equal(cgroup.TrimEnd('\n')[3..], path);
    }

    [Fact]
    public void Boot_time_comes_from_the_btime_line()
    {
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1790770000),
            KernelStat.BootTime("cpu  1 2 3\nintr 5\nbtime 1790770000\nprocesses 99\n"));
        Assert.Throws<FormatException>(() => KernelStat.BootTime("cpu 1\n"));
    }

    [Fact]
    public void Every_captured_distro_parses()
    {
        Assert.NotEmpty(Distros());
        foreach (var distro in Distros())
        {
            var stat = ProcStat.Parse(Fixture(distro, "pid-stat")!);
            Assert.Equal("cat", stat.Name);
            Assert.NotNull(ProcStatus.Parse(Fixture(distro, "pid-status")!).RealUserId);
            Assert.StartsWith("/", CgroupPath.Parse(Fixture(distro, "pid-cgroup")!), StringComparison.Ordinal);
            Assert.True(KernelStat.BootTime(Fixture(distro, "kernel-stat")!) > DateTimeOffset.UnixEpoch);

            if (Fixture(distro, "container-cgroup") is { } containerCgroup)
            {
                Assert.Equal("docker", CgroupPath.ContainerOf(containerCgroup)?.Runtime);
                Assert.Equal(1, ProcStatus.Parse(Fixture(distro, "container-status")!).InnermostProcessId);
            }
        }
    }
}
