using System.Diagnostics;
using LinuxDiag.Mcp.Diagnostics.Access;
using LinuxDiag.Mcp.Linux.Native;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Tools;
using static LinuxDiag.Mcp.Tests.AccessFormatTests;

namespace LinuxDiag.Mcp.Tests;

public sealed class AccessTests : IDisposable
{
    private static readonly AccessSubject Alice = new("alice (uid 1000)", 1000, "alice", [1000, 4], false, false);
    private static readonly AccessSubject Root = new("root (uid 0)", 0, "root", [0], true, true);

    private readonly string _root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld-access-{Guid.NewGuid():N}")).FullName;

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    private static FileFacts Facts(uint owner, uint group, int permissions, IReadOnlyList<AclEntry>? acl = null, bool directory = false) =>
        new(owner, group, permissions, directory, acl, false, false, false, false, IsRegular: !directory);

    [Fact]
    public void The_owner_is_judged_by_the_owner_bits_alone_even_when_other_would_allow()
    {
        var file = Facts(1000, 1000, 0b000_100_111);

        var (allowed, reason) = PosixAccess.Check(Alice, file, AccessRights.Read);

        Assert.False(allowed);
        Assert.StartsWith("owner (uid 1000): ---", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void A_group_member_uses_the_group_bits_and_never_falls_through_to_other()
    {
        Assert.True(PosixAccess.Check(Alice, Facts(0, 4, 0b110_100_000), AccessRights.Read).Allowed);
        var (allowed, reason) = PosixAccess.Check(Alice, Facts(0, 4, 0b110_000_110), AccessRights.Read);

        Assert.False(allowed);
        Assert.Contains("group class", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void A_named_user_entry_is_limited_by_the_mask()
    {
        var acl = PosixAcl.Parse(Acl((0x01, 6, Undefined), (0x02, 7, 1000), (0x04, 4, Undefined), (0x10, 4, Undefined), (0x20, 0, Undefined)));

        Assert.True(PosixAccess.Check(Alice, Facts(0, 0, 0b110_100_000, acl), AccessRights.Read).Allowed);
        var (allowed, reason) = PosixAccess.Check(Alice, Facts(0, 0, 0b110_100_000, acl), AccessRights.Write);

        Assert.False(allowed);
        Assert.Contains("limited by mask::r--", reason, StringComparison.Ordinal);

        var voided = PosixAcl.Parse(Acl((0x01, 6, Undefined), (0x02, 7, 1000), (0x04, 0, Undefined), (0x10, 0, Undefined), (0x20, 4, Undefined)));
        Assert.StartsWith("other class", PosixAccess.Check(Alice, Facts(0, 0, 0b110_000_100, voided), AccessRights.Read).Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void A_matching_group_entry_that_grants_nothing_stops_the_check_before_other()
    {
        // Review Focus 5: other::r-- would allow, but alice's own group matched first.
        var acl = PosixAcl.Parse(Acl((0x01, 6, Undefined), (0x04, 0, Undefined), (0x08, 0, 4), (0x10, 7, Undefined), (0x20, 4, Undefined)));

        var (allowed, reason) = PosixAccess.Check(Alice, Facts(0, 1000, 0b110_111_100, acl), AccessRights.Read);

        Assert.False(allowed);
        Assert.Contains("stops the check before other", reason, StringComparison.Ordinal);
        Assert.True(PosixAccess.Check(Alice with { Groups = [5] }, Facts(0, 1000, 0b110_111_100, acl), AccessRights.Read).Allowed);
    }

    [Fact]
    public void Root_reads_and_writes_past_the_bits_but_executes_only_what_some_class_may_execute()
    {
        var (read, why) = PosixAccess.Check(Root, Facts(1000, 1000, 0b110_000_000), AccessRights.Read);

        Assert.True(read);
        Assert.Contains("CAP_DAC_OVERRIDE", why, StringComparison.Ordinal);
        Assert.True(PosixAccess.Check(Root, Facts(1000, 1000, 0b110_000_000), AccessRights.Write).Allowed);
        Assert.False(PosixAccess.Check(Root, Facts(1000, 1000, 0b110_000_000), AccessRights.Execute).Allowed);
        Assert.True(PosixAccess.Check(Root, Facts(1000, 1000, 0b111_000_000), AccessRights.Execute).Allowed);
        Assert.True(PosixAccess.Check(Root, Facts(1000, 1000, 0b000_000_000, directory: true), AccessRights.Execute).Allowed);
    }

    [Fact]
    public void Read_search_alone_opens_directories_for_listing_and_traversal_but_not_for_writing()
    {
        var reader = Alice with { DacReadSearch = true };
        var directory = Facts(0, 0, 0b111_000_000, directory: true);

        Assert.True(PosixAccess.Check(reader, directory, AccessRights.Execute).Allowed);
        Assert.True(PosixAccess.Check(reader, directory, AccessRights.Read).Allowed);
        Assert.False(PosixAccess.Check(reader, directory, AccessRights.Write).Allowed);
        Assert.False(PosixAccess.Check(reader, Facts(0, 0, 0b111_000_000), AccessRights.Execute).Allowed);
    }

    [Fact]
    public void A_read_only_mount_an_immutable_file_and_a_noexec_mount_refuse_even_root()
    {
        // Review Focus 5.
        var open = Facts(0, 0, 0b111_111_111);

        Assert.Contains("read-only", PosixAccess.Check(Root, open with { ReadOnlyMount = true }, AccessRights.Write).Reason, StringComparison.Ordinal);
        Assert.False(PosixAccess.Check(Root, open with { ReadOnlyMount = true }, AccessRights.Write).Allowed);
        Assert.False(PosixAccess.Check(Root, open with { Immutable = true }, AccessRights.Write).Allowed);
        Assert.Contains("immutable", PosixAccess.Check(Root, open with { Immutable = true }, AccessRights.Write).Reason, StringComparison.Ordinal);
        Assert.False(PosixAccess.Check(Root, open with { NoExecMount = true }, AccessRights.Execute).Allowed);
        Assert.True(PosixAccess.Check(Root, open with { NoExecMount = true, IsDirectory = true, IsRegular = false }, AccessRights.Execute).Allowed);
        Assert.True(PosixAccess.Check(Root, open with { ReadOnlyMount = true, IsRegular = false }, AccessRights.Write).Allowed);
    }

    [Fact]
    public void The_kernel_disagreeing_with_the_bits_for_the_same_account_is_called_out_and_otherwise_not()
    {
        var allowed = new AccessDecision(true, "owner (uid 1000): rw-");
        var denied = new AccessDecision(false, "owner (uid 1000): rw-");

        var same = LinuxAccessInspector.ProbeNotes(allowed, allowed, denied, new ServerProbe(1000, true, false, false, SameSubject: true)).ToList();
        var other = LinuxAccessInspector.ProbeNotes(allowed, allowed, denied, new ServerProbe(0, true, false, false, SameSubject: false)).ToList();

        Assert.Contains("denies write", Assert.Single(same), StringComparison.Ordinal);
        Assert.Contains("AppArmor", same[0], StringComparison.Ordinal);
        Assert.Empty(other);
    }

    [Fact]
    public void Every_ancestor_of_a_path_is_listed_from_the_root_down()
    {
        Assert.Equal(["/", "/srv", "/srv/data"], LinuxAccessInspector.Ancestors("/srv/data/report.csv"));
        Assert.Empty(LinuxAccessInspector.Ancestors("/"));
    }

    [Fact]
    public void The_summary_leads_with_the_subject_and_the_verdicts_and_names_where_the_path_is_blocked()
    {
        var report = new EffectiveAccessReport(
            "/srv/data/report.csv", null, "regular file", "root (0)", "root (0)", "0640 rw-r-----", [], [], null, false, false,
            "/", ["rw"], new AccessSubject("nobody (uid 65534)", 65534, "nobody", [65534], false, false),
            new AccessDecision(false, "cannot reach the file: no search permission on /srv/data"),
            new AccessDecision(false, "cannot reach the file: no search permission on /srv/data"),
            new AccessDecision(false, "cannot reach the file: no search permission on /srv/data"),
            [new PathStep("/", true, "other class: r-x"), new PathStep("/srv/data", false, "other class: ---")], "/srv/data",
            new ServerProbe(0, true, true, false, false), ["AppArmor and SELinux policy is not evaluated."]);

        var summary = AccessTools.Render(report);

        Assert.StartsWith("nobody (uid 65534) on /srv/data/report.csv (regular file)", summary, StringComparison.Ordinal);
        Assert.Contains("Read:    DENIED - cannot reach", summary, StringComparison.Ordinal);
        Assert.Contains("BLOCKED at /srv/data: other class: ---", summary, StringComparison.Ordinal);
        Assert.Contains("Server's own kernel check (uid 0): read yes, write yes, execute no", summary, StringComparison.Ordinal);
    }

    [LinuxFact]
    public void Status_reads_the_same_owner_group_and_mode_stat_reports()
    {
        // Pins the statx offsets: uid 20, gid 24, mode 28. /etc/shadow is root:shadow (0:42), so a uid read
        // from the gid's offset cannot pass -- a file of the test user's own has uid == gid, and would.
        var fields = Output("stat", "-L", "-c", "%u %g %f", "/etc/shadow").Split(' ');
        var status = LibC.Status("/etc/shadow")!.Value;

        Assert.NotEqual(fields[0], fields[1]);

        Assert.Equal(uint.Parse(fields[0], System.Globalization.CultureInfo.InvariantCulture), status.UserId);
        Assert.Equal(uint.Parse(fields[1], System.Globalization.CultureInfo.InvariantCulture), status.GroupId);
        Assert.Equal(Convert.ToUInt16(fields[2], 16), status.Mode);
        Assert.Null(LibC.Status(Path.Combine(_root, "missing")));
    }

    [LinuxFact]
    public void Account_lookups_agree_with_id()
    {
        var me = LibC.UserByName(Environment.UserName)!;

        Assert.Equal(Output("id", "-u"), me.UserId.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal(
            Output("id", "-G").Split(' ').Select(g => uint.Parse(g, System.Globalization.CultureInfo.InvariantCulture)).Order(),
            LibC.GroupsOf(me.Name, me.GroupId).Order());
        Assert.Equal(0u, LibC.UserByName("root")!.UserId);
        Assert.Equal("root", LibC.UserById(0)!.Name);
        Assert.Equal("root", LibC.GroupName(0));
        Assert.Null(LibC.UserByName("no-such-account-ld"));
    }

    [LinuxFact]
    public void An_acl_entry_lets_nobody_read_a_file_its_mode_alone_refuses()
    {
        var file = Path.Combine(_root, "secret");
        File.WriteAllText(file, "x");
        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var nobody = LibC.UserByName("nobody")!.UserId;
        var inspector = new LinuxAccessInspector();

        var before = inspector.Inspect(file, "nobody", null);
        SetAcl(file, Acl((0x01, 6, Undefined), (0x02, 4, nobody), (0x04, 0, Undefined), (0x10, 4, Undefined), (0x20, 0, Undefined)));
        var after = inspector.Inspect(file, "nobody", null);

        Assert.False(before.Read.Allowed);
        Assert.Contains("other class", before.Read.Reason, StringComparison.Ordinal);
        Assert.True(after.Read.Allowed);
        Assert.Contains("named user", after.Read.Reason, StringComparison.Ordinal);
        Assert.False(after.Write.Allowed);
        Assert.Contains(after.Acl, e => e.StartsWith("user:nobody:r--", StringComparison.Ordinal));
    }

    [LinuxFact]
    public void A_directory_the_account_cannot_search_blocks_the_file_and_is_named()
    {
        var directory = Directory.CreateDirectory(Path.Combine(_root, "private")).FullName;
        File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var file = Path.Combine(directory, "open");
        File.WriteAllText(file, "x");
        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        var report = new LinuxAccessInspector().Inspect(file, "nobody", null);

        Assert.Equal(directory, report.BlockedAt);
        Assert.False(report.Read.Allowed);
        Assert.StartsWith("cannot reach the file", report.Read.Reason, StringComparison.Ordinal);
        Assert.Contains(report.Traversal, s => s.Path == "/" && s.CanSearch);
    }

    [LinuxFact]
    public void Evaluating_the_servers_own_process_agrees_with_the_kernels_own_answer()
    {
        var file = Path.Combine(_root, "mine");
        File.WriteAllText(file, "x");
        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.GroupRead);

        foreach (var path in new[] { file, _root })
        {
            var report = new LinuxAccessInspector().Inspect(path, null, Environment.ProcessId);

            Assert.True(report.Probe.SameSubject);
            Assert.Equal(report.Probe.Read, report.Read.Allowed);
            Assert.Equal(report.Probe.Write, report.Write.Allowed);
            Assert.Equal(report.Probe.Execute, report.Execute.Allowed);
            Assert.DoesNotContain(report.Notes, n => n.StartsWith("The kernel", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void Exactly_one_subject_is_required()
    {
        var inspector = new LinuxAccessInspector();

        Assert.Throws<ArgumentException>(() => inspector.Inspect("/etc/passwd", null, null));
        Assert.Throws<ArgumentException>(() => inspector.Inspect("/etc/passwd", "root", 1));
    }

    private static void SetAcl(string path, byte[] acl) =>
        LockParserTests.Run("python3", "-c",
            "import os,sys; os.setxattr(sys.argv[1], 'system.posix_acl_access', bytes.fromhex(sys.argv[2]))",
            path, Convert.ToHexString(acl));

    private static string Output(string program, params string[] arguments)
    {
        using var process = Process.Start(new ProcessStartInfo(program, arguments) { RedirectStandardOutput = true })!;
        var output = process.StandardOutput.ReadToEnd().Trim();
        process.WaitForExit();
        return output;
    }
}
