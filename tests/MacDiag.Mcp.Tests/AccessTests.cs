using System.Collections;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Access;
using MacDiag.Mcp.Diagnostics.Handles;
using MacDiag.Mcp.Mac.Parsers;
using MacDiag.Mcp.Tools;
using static MacDiag.Mcp.Tests.StatLinesTests;
using static MacDiag.Mcp.Tests.SystemOverviewTests;

namespace MacDiag.Mcp.Tests;

public sealed class AccessTests
{
    private const string Report = "/Users/Shared/report.txt";

    /// <summary>A Mac whose kernel answers /bin/test from a table, for whichever uid asks.</summary>
    private sealed class FakeMac
    {
        public uint ServerUid { get; set; }

        public Dictionary<string, string> Stats { get; } = new()
        {
            [Report] = Line(Report, 0, 0, "0644", "Regular File"),
        };

        public string Acl { get; set; } = "-rw-r--r--  1 root  wheel  1024 Oct  1 09:00 /Users/Shared/report.txt\n";

        /// <summary>Allowed (uid, flag, path) triples; anything else is denied.</summary>
        public HashSet<(uint, string, string)> Allowed { get; } = [];

        public ExternalResult? SudoFailure { get; set; }

        public string GroupNames { get; set; } = "staff everyone localaccounts";

        public string GroupIds { get; set; } = "20 12 61";

        public Dictionary<string, int> GroupGids { get; } = new()
        {
            ["staff"] = 20, ["everyone"] = 12, ["admin"] = 80, ["wheel"] = 0, ["Domain Users"] = 1234, ["Domain"] = 999,
        };

        public Func<string, string> Resolve { get; set; } = path => path;

        public FakeCommands Commands { get; private set; } = null!;

        public MacAccessInspector Inspector()
        {
            Commands = new FakeCommands(Answer);
            return new MacAccessInspector(Commands, MacDiagOptions.FromEnvironment(new Hashtable()))
            {
                Resolve = Resolve,
                Firmlinks = PathSpellings.BuiltInFirmlinks,
            };
        }

        private ExternalResult Test(uint uid, IReadOnlyList<string> args) =>
            new(Allowed.Contains((uid, args[^2], args[^1])) ? 0 : 1, "", "");

        private ExternalResult Answer(string program, IReadOnlyList<string> args) => program switch
        {
            "id" when args.Count == 1 => FakeCommands.Ok($"{ServerUid}\n"),
            "id" when args[0] == "-u" => args[^1] switch { "alice" => FakeCommands.Ok("501\n"), "root" => FakeCommands.Ok("0\n"), _ => new ExternalResult(1, "", "id: no such user") },
            "id" when args[0] == "-un" => args[^1] switch { "501" => FakeCommands.Ok("alice\n"), "0" => FakeCommands.Ok("root\n"), _ => new ExternalResult(1, "", "id: no such user") },
            "id" when args[0] == "-Gn" => FakeCommands.Ok(args[^1] is "501" or "alice" ? GroupNames + "\n" : "wheel daemon\n"),
            "id" when args[0] == "-G" => FakeCommands.Ok(args[^1] is "501" or "alice" ? GroupIds + "\n" : "0 1\n"),
            "dscacheutil" => GroupGids.TryGetValue(args[^1], out var gid) ? FakeCommands.Ok($"name: {args[^1]}\npassword: *\ngid: {gid}\n\n") : FakeCommands.Ok(""),
            "ps" => args[1] == "4242" ? FakeCommands.Ok("  501\n") : new ExternalResult(1, "", ""),
            "stat" when args[1] == "%Su" => FakeCommands.Ok("root\n"),
            "stat" when args[1] == "%Sg" => FakeCommands.Ok("wheel\n"),
            "stat" => Answer(Stats, args),
            "ls" => FakeCommands.Ok(Acl),
            "mount" => FakeCommands.Ok(Fixture(Unverified, "mount")),
            "test" => Test(ServerUid, args),
            "sudo" => SudoFailure ?? Test(uint.Parse(args[2][1..], System.Globalization.CultureInfo.InvariantCulture), args),
            _ => new ExternalResult(1, "", $"unexpected {program}"),
        };

        private static ExternalResult Answer(Dictionary<string, string> stats, IReadOnlyList<string> args) => StatLinesTests.Answer(stats, args);
    }

    private static Task<EffectiveAccessReport> Inspect(FakeMac mac, string? account = "alice", int? processId = null, string path = Report) =>
        mac.Inspector().InspectAsync(path, account, processId, CancellationToken.None);

    [Theory]
    [InlineData("-u root")]
    [InlineData("a;b")]
    [InlineData("../x")]
    [InlineData("-n")]
    [InlineData("alice bob")]
    public async Task An_account_that_is_not_a_plain_name_or_uid_is_refused_before_any_program_runs(string account)
    {
        var mac = new FakeMac();

        await Assert.ThrowsAsync<ArgumentException>(() => Inspect(mac, account));
        Assert.Empty(mac.Commands.Calls);
    }

    [Fact]
    public async Task A_relative_path_or_both_or_neither_subject_is_refused()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => Inspect(new FakeMac(), path: "report.txt"));
        await Assert.ThrowsAsync<ArgumentException>(() => Inspect(new FakeMac(), "alice", 4242));
        await Assert.ThrowsAsync<ArgumentException>(() => Inspect(new FakeMac(), null, null));
    }

    [Fact]
    public async Task As_root_the_kernel_is_asked_as_the_account_through_sudo_and_its_answer_is_the_decision()
    {
        var mac = new FakeMac();
        mac.Allowed.Add((501, "-r", Report));
        mac.Allowed.Add((501, "-x", "/"));
        mac.Allowed.Add((501, "-x", "/Users"));
        mac.Allowed.Add((501, "-x", "/Users/Shared"));

        var report = await Inspect(mac);

        Assert.Equal((true, false, false), (report.Read.Allowed, report.Write.Allowed, report.Execute.Allowed));
        Assert.Contains(mac.Commands.Calls, c => c.Program == "sudo" && c.Arguments.SequenceEqual(["-n", "-u", "#501", "/bin/test", "-r", Report]));
        Assert.Equal(("alice", 501u), (report.Subject.UserName, report.Subject.UserId));
        Assert.Contains("staff", report.Subject.Groups);
        Assert.Null(report.BlockedAt);
    }

    [Fact]
    public async Task The_test_is_never_given_a_double_dash_which_bsd_test_would_read_as_its_operand()
    {
        var mac = new FakeMac();

        await Inspect(mac, "root");

        Assert.DoesNotContain(mac.Commands.Calls.Where(c => c.Program is "test" or "sudo"), c => c.Arguments.Contains("--"));
    }

    [Fact]
    public async Task A_server_that_is_not_root_evaluates_nobody_else_and_says_so_instead_of_answering_for_itself()
    {
        var mac = new FakeMac { ServerUid = 502 };
        mac.Allowed.Add((502, "-r", Report));

        var report = await Inspect(mac);

        Assert.Equal((null, null, null), (report.Read.Allowed, report.Write.Allowed, report.Execute.Allowed));
        Assert.Contains("needs root", report.Read.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain(mac.Commands.Calls, c => c.Program == "sudo");
        Assert.False(report.Probe.SameSubject);
        Assert.True(report.Probe.Read);
    }

    [Fact]
    public async Task The_servers_own_account_is_asked_directly()
    {
        var mac = new FakeMac { ServerUid = 501 };
        mac.Allowed.Add((501, "-w", Report));

        var report = await Inspect(mac);

        Assert.True(report.Write.Allowed);
        Assert.True(report.Probe.SameSubject);
        Assert.DoesNotContain(mac.Commands.Calls, c => c.Program == "sudo");
    }

    [Fact]
    public async Task A_sudo_failure_is_not_evaluated_never_denied()
    {
        var mac = new FakeMac { SudoFailure = new ExternalResult(1, "", "sudo: unknown user #501\n") };

        var report = await Inspect(mac);

        Assert.Null(report.Read.Allowed);
        Assert.Contains("not evaluated", report.Read.Reason, StringComparison.Ordinal);
        Assert.Contains("unknown user", report.Read.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_test_that_exits_2_is_not_evaluated_never_denied()
    {
        var mac = new FakeMac { SudoFailure = new ExternalResult(2, "", "test: unexpected operator\n") };

        var report = await Inspect(mac);

        Assert.Null(report.Write.Allowed);
    }

    [Fact]
    public async Task The_first_directory_the_subject_cannot_search_is_where_it_is_blocked()
    {
        var mac = new FakeMac();
        mac.Allowed.Add((501, "-x", "/"));

        var report = await Inspect(mac);

        Assert.Equal("/Users", report.BlockedAt);
        Assert.Equal(["/", "/Users", "/Users/Shared"], report.Traversal.Select(s => s.Path));
        Assert.Equal(true, report.Traversal[0].CanSearch);
        Assert.Equal(false, report.Traversal[1].CanSearch);
    }

    [Fact]
    public void Acl_entries_are_read_from_ls_without_their_index()
    {
        Assert.Equal(["group:everyone deny delete", "user:admin allow read,write", "group:staff deny write,append inherited"],
            LsAcl.Parse(Fixture(Unverified, "ls-lde")));
        Assert.Empty(LsAcl.Parse("-rw-r--r--  1 root  wheel  0 Oct  1 09:00 /x\n"));
    }

    [Fact]
    public async Task A_deny_entry_for_everyone_or_one_of_the_subjects_groups_is_named_and_one_for_others_is_not()
    {
        var mac = new FakeMac { Acl = Fixture(Unverified, "ls-lde") };

        var report = await Inspect(mac);

        Assert.Equal(3, report.Acl.Count);
        Assert.Contains(report.Notes, n => n.Contains("group:everyone deny delete", StringComparison.Ordinal));
        Assert.Contains(report.Notes, n => n.Contains("group:staff deny write,append inherited", StringComparison.Ordinal));
        Assert.DoesNotContain(report.Notes, n => n.Contains("user:admin", StringComparison.Ordinal));
    }

    [Fact]
    public void An_acl_entry_for_a_group_whose_name_has_spaces_is_read_whole()
    {
        Assert.Equal(["group:Domain Users deny write,append", "user:admin allow read"],
            LsAcl.Parse(" 0: group:Domain Users deny write,append\n 1: user:admin allow read\n"));
    }

    [Fact]
    public async Task A_deny_entry_for_a_directory_group_whose_name_has_spaces_is_named_and_the_group_kept_whole()
    {
        var mac = new FakeMac
        {
            Acl = " 0: group:Domain Users deny write,append\n 1: group:Domain deny read\n",
            GroupNames = "staff Domain Users everyone",
            GroupIds = "20 1234 12",
        };

        var report = await Inspect(mac);

        Assert.Contains(report.Notes, n => n.Contains("group:Domain Users deny", StringComparison.Ordinal));
        Assert.DoesNotContain(report.Notes, n => n.Contains("'group:Domain deny", StringComparison.Ordinal));
        Assert.Equal(["staff Domain Users everyone"], report.Subject.Groups);
    }

    [Fact]
    public async Task A_link_this_server_may_not_follow_is_an_error_the_caller_reads()
    {
        var mac = new FakeMac { Resolve = _ => throw new UnauthorizedAccessException("Access to the path is denied.") };

        await Assert.ThrowsAsync<AccessInspectionException>(() => Inspect(mac));
    }

    [Fact]
    public async Task An_immutable_or_sip_protected_file_is_explained()
    {
        var mac = new FakeMac();
        mac.Stats[Report] = Line(Report, 0, 0, "0644", "Regular File", "uchg,restricted");

        var report = await Inspect(mac);

        Assert.Equal(["uchg", "restricted"], report.Flags);
        Assert.Contains(report.Notes, n => n.Contains("immutable", StringComparison.Ordinal));
        Assert.Contains(report.Notes, n => n.Contains("System Integrity Protection protects", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_path_under_Users_is_on_the_data_volume_not_the_sealed_read_only_root()
    {
        var report = await Inspect(new FakeMac());

        Assert.Equal("/System/Volumes/Data", report.MountPoint);
        Assert.DoesNotContain(report.Notes, n => n.Contains("read-only mount", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_file_on_the_sealed_volume_is_on_a_read_only_mount()
    {
        var mac = new FakeMac();
        mac.Stats["/usr/bin/true"] = Line("/usr/bin/true", 0, 0, "0755", "Regular File");

        var report = await Inspect(mac, path: "/usr/bin/true");

        Assert.Equal("/", report.MountPoint);
        Assert.Contains(report.Notes, n => n.Contains("read-only mount", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_process_is_evaluated_as_its_user()
    {
        var mac = new FakeMac();
        mac.Allowed.Add((501, "-r", Report));

        var report = await Inspect(mac, null, 4242);

        Assert.Equal(501u, report.Subject.UserId);
        Assert.True(report.Read.Allowed);
        Assert.Contains(report.Notes, n => n.Contains("evaluated as its user", StringComparison.Ordinal));
    }

    [Fact]
    public async Task An_unknown_account_a_missing_process_and_a_path_that_cannot_be_statted_are_errors_the_caller_reads()
    {
        await Assert.ThrowsAsync<AccessInspectionException>(() => Inspect(new FakeMac(), "nobodyhere"));
        await Assert.ThrowsAsync<AccessInspectionException>(() => Inspect(new FakeMac(), null, 999));
        await Assert.ThrowsAsync<AccessInspectionException>(() => Inspect(new FakeMac(), path: "/nope"));
    }

    [Fact]
    public async Task The_summary_says_sip_and_privacy_rules_are_not_evaluated()
    {
        var report = await Inspect(new FakeMac());

        var summary = AccessTools.Render(report);

        Assert.Contains("Privacy (TCC)", summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Read:", summary, StringComparison.Ordinal);
        Assert.Contains("mode 0644 rw-r--r--", summary, StringComparison.Ordinal);
    }
}
