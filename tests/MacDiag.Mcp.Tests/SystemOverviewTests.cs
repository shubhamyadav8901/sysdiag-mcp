using MacDiag.Mcp.Diagnostics.SystemInfo;
using MacDiag.Mcp.Mac.Parsers;
using MacDiag.Mcp.Tools;

namespace MacDiag.Mcp.Tests;

public sealed class SystemOverviewTests
{
    /// <summary>The fixtures written from Apple's documentation: the values the tests below pin.</summary>
    internal const string Unverified = "macos-unverified";

    /// <summary>Output captured on a real Mac by tools/capture-macos-fixtures.sh: checked for shape only.</summary>
    internal const string Captured = "macos";

    /// <summary>A fixture's text from the named set, with its comment lines removed.</summary>
    internal static string Fixture(string set, string name) =>
        string.Join('\n', File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "Fixtures", set, name)).Where(l => !l.StartsWith('#')));

    [Fact]
    public void Sw_vers_gives_name_version_and_build()
    {
        Assert.Equal(new SwVersInfo("macOS", "14.6.1", "23G93"), SwVers.Parse(Fixture(Unverified, "sw_vers")));
    }

    [Fact]
    public void Sysctl_values_come_in_the_order_asked_and_boottime_is_read_from_its_struct_text()
    {
        var values = Sysctl.ParseValues(Fixture(Unverified, "sysctl"), 4);

        Assert.Equal("Mac14,2", values[0]);
        Assert.Equal("17179869184", values[1]);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1727762400), Sysctl.BootTime(values[3]));
        Assert.Null(Sysctl.BootTime("not a struct"));
    }

    [Fact]
    public void A_sysctl_answer_with_a_value_missing_is_refused_rather_than_shifted()
    {
        Assert.Throws<FormatException>(() => Sysctl.ParseValues("Mac14,2\n23.6.0\n", 4));
    }

    [Fact]
    public void Available_memory_is_free_inactive_and_speculative_pages_at_the_page_size_the_header_states()
    {
        var memory = VmStat.Parse(Fixture(Unverified, "vm_stat"));

        Assert.Equal(16384, memory.PageSize);
        Assert.Equal((12345L + 200000 + 5000) * 16384, memory.AvailableBytes);
    }

    [Fact]
    public void Mounts_keep_spaces_in_the_mount_point_and_read_only_and_file_system_from_the_options()
    {
        var mounts = MountList.Parse(Fixture(Unverified, "mount"));

        var root = mounts.Single(m => m.MountPoint == "/");
        Assert.True(root.ReadOnly);
        Assert.Equal("apfs", root.FileSystem);
        Assert.Contains(mounts, m => m.MountPoint == "/Volumes/My Backup");
        Assert.Equal("/dev/disk6s1", mounts.Single(m => m.MountPoint == "/Volumes/Back on (old)").Device);
        Assert.Equal("smbfs", mounts.Single(m => m.MountPoint == "/Volumes/share").FileSystem);
    }

    [Fact]
    public void Each_apfs_container_is_reported_once_by_its_writable_volume_and_system_internal_volumes_never()
    {
        // APFS volumes in one container share its free space, so / and /System/Volumes/Data would report the
        // same number twice; the sealed system volume is the one dropped.
        var shown = MountList.ForSpace(MountList.Parse(Fixture(Unverified, "mount"))).Select(m => m.MountPoint).ToArray();

        Assert.Equal(["/System/Volumes/Data", "/Volumes/My Backup", "/Volumes/Back on (old)", "/Volumes/share"], shown);
    }

    [Fact]
    public void A_sealed_root_with_no_writable_sibling_is_still_shown()
    {
        var shown = MountList.ForSpace(MountList.Parse("/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)\n"));

        Assert.Equal("/", Assert.Single(shown).MountPoint);
    }

    [Fact]
    public void A_line_in_an_unexpected_shape_is_skipped_and_an_unknown_vm_stat_line_is_ignored()
    {
        // Review Focus 4: tool output that differs from the documented shape is read as far as it is recognised.
        Assert.Single(MountList.Parse("garbage\n/dev/disk3s5 on /System/Volumes/Data (apfs, local)\n"));
        Assert.Equal(4096, VmStat.Parse("Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 1.\nSomething new: 7.\n").PageSize);
        Assert.Null(SwVers.Parse("ProductVersion: 14.6\n").Name);
    }

    [Fact]
    public void The_summary_names_the_version_model_and_a_nearly_full_data_volume_but_never_a_read_only_volume()
    {
        var overview = new SystemOverview("mac1", "root", "macOS 14.6.1 (23G93)", "Darwin 23.6.0", "Arm64", "Mac14,2", true,
            DateTimeOffset.UnixEpoch, TimeSpan.FromHours(5), 8, 16L << 30, 4L << 30,
            [new MountedFilesystem("/", "/dev/disk3s1s1", "apfs", 100, 1, true),
             new MountedFilesystem("/System/Volumes/Data", "/dev/disk3s5", "apfs", 100, 2, false)],
            ["vm_stat failed: boom"]);

        var summary = SystemTools.RenderOverview(overview);

        Assert.Contains("macOS 14.6.1 (23G93)", summary, StringComparison.Ordinal);
        Assert.Contains("Mac14,2", summary, StringComparison.Ordinal);
        Assert.Contains("WARNING: vm_stat failed: boom", summary, StringComparison.Ordinal);
        Assert.Equal(1, summary.Split("CRITICALLY LOW").Length - 1);
    }

    public static TheoryData<string> CapturedFixtures()
    {
        var data = new TheoryData<string>();
        var directory = Path.Combine(AppContext.BaseDirectory, "Fixtures", Captured);
        foreach (var name in new[] { "sw_vers", "sysctl", "vm_stat", "mount", "lsof-p", "lsof-i", "ps-args", "ps-comm", "launchctl-print-sshd", "launchctl-list", "launchctl-print-disabled", "plist-sshd.xml", "log-ndjson", "codesign-dvvv-apple", "pkgutil-file-info", "ls-lde", "stat-lines", "systemextensionsctl-list", "kmutil-showloaded", "sfltool-dumpbtm" }.Where(n => File.Exists(Path.Combine(directory, n)) && new FileInfo(Path.Combine(directory, n)).Length > 0))
        {
            data.Add(name);
        }

        if (data.Count == 0)
        {
            data.Add("(none captured)");
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(CapturedFixtures))]
    public void Every_parser_reads_output_captured_on_a_real_mac(string name)
    {
        if (name == "(none captured)")
        {
            // Reported, not passed silently: xUnit 2 has no dynamic skip, so the case says what it is.
            Assert.False(Directory.Exists(Path.Combine(AppContext.BaseDirectory, "Fixtures", Captured)), "captures exist but none matched");
            return;
        }

        var text = Fixture(Captured, name);
        switch (name)
        {
            case "sw_vers":
                Assert.NotNull(SwVers.Parse(text).Version);
                break;
            case "sysctl":
                Assert.NotNull(Sysctl.BootTime(Sysctl.ParseValues(text, 4)[3]));
                break;
            case "vm_stat":
                var memory = VmStat.Parse(text);
                Assert.Contains(memory.PageSize, new long?[] { 4096, 16384 });
                Assert.True(memory.AvailableBytes > 0, string.Join(", ", memory.Missing));
                break;
            case "mount":
                Assert.Contains(MountList.Parse(text), m => m.MountPoint == "/");
                break;
            case "ps-args":
                var (rows, _) = PsTable.ParseArgs(text);
                Assert.True(rows.Count >= 10, $"{rows.Count} rows");
                Assert.Contains(rows, r => r.ProcessId == 1);
                Assert.All(rows, r => Assert.NotNull(r.Start));
                break;
            case "ps-comm":
                Assert.Contains("/sbin/launchd", PsTable.ParseComm(text).Commands[1].Command, StringComparison.Ordinal);
                break;
            case "launchctl-print-sshd":
                Assert.NotNull(LaunchctlPrint.State(text).State);
                break;
            case "launchctl-list":
                Assert.True(LaunchctlList.Parse(text).Count >= 20);
                break;
            case "launchctl-print-disabled":
                Assert.NotEmpty(LaunchctlDisabled.Parse(text));
                break;
            case "plist-sshd.xml":
                Assert.Equal("com.openssh.sshd", PlistXml.Parse(text).String("Label"));
                break;
            case "log-ndjson":
                Assert.Contains(text.Split('\n').Select(LogNdjson.Parse), l => l?.Kind == LogLineKind.Event);
                break;
            case "codesign-dvvv-apple":
                Assert.True(CodesignDisplay.Details(text).SignedByApple, text);
                break;
            case "pkgutil-file-info":
                // /bin/ls may or may not have a receipt on a sealed system; a receipt that is there must parse whole.
                var (package, version) = PkgutilFileInfo.Parse(text);
                Assert.True(package is null || version is not null, text);
                break;
            case "ls-lde":
                // A user's home carries "group:everyone deny delete" on every macOS release: an empty list would be a parser miss.
                Assert.Contains(LsAcl.Parse(text), entry => entry.StartsWith("group:everyone deny ", StringComparison.Ordinal));
                break;
            case "stat-lines":
                Assert.Equal([StatKind.Directory, StatKind.File, StatKind.CharacterDevice], StatLines.Parse(text).Select(l => l.Kind));
                break;
            case "systemextensionsctl-list":
                Assert.True(SystemExtensions.Parse(text).Count > 0 || SystemExtensions.SaysNone(text), text);
                break;
            case "kmutil-showloaded":
                Assert.NotEmpty(KextList.Parse(text));
                break;
            case "sfltool-dumpbtm":
                Assert.True(BtmDump.Parse(text).Count > 0 || !text.Contains("#1:", StringComparison.Ordinal), text);
                break;
            case "lsof-p":
                // Read raw: lsof's NUL-separated fields are not lines, and nothing in them is a comment.
                Assert.Contains(Mac.Parsers.LsofFields.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", Captured, name))),
                    p => p.Files.Any(f => f.Descriptor == "txt"));
                break;
            case "lsof-i":
                Assert.Contains(Mac.Parsers.LsofFields.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", Captured, name))),
                    p => p.Files.Any(f => f.Protocol is not null));
                break;
        }
    }
}
