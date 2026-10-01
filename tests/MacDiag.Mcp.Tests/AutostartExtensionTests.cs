using MacDiag.Mcp.Diagnostics.Autostart;
using MacDiag.Mcp.Mac.Parsers;
using static MacDiag.Mcp.Tests.AutostartTests;
using static MacDiag.Mcp.Tests.StatLinesTests;
using static MacDiag.Mcp.Tests.SystemOverviewTests;

namespace MacDiag.Mcp.Tests;

public sealed class AutostartExtensionTests
{
    private static Task<AutostartAuditResult> Audit(FakeMac mac, AutostartQuery query) =>
        mac.Inspector().AuditAsync(query, CancellationToken.None);

    [Fact]
    public void System_extensions_are_read_from_their_tab_separated_rows_with_empty_columns_allowed()
    {
        var extensions = SystemExtensions.Parse(Fixture(Unverified, "systemextensionsctl-list"));

        Assert.Equal(3, extensions.Count);
        var vpn = extensions[0];
        Assert.Equal(("com.apple.system_extension.network_extension", true, true, "ABCDE12345"), (vpn.Kind, vpn.Enabled, vpn.Active, vpn.TeamId));
        Assert.Equal(("com.example.vpn.extension", "1.2.3/45", "Example VPN", "activated enabled"), (vpn.BundleId, vpn.Version, vpn.Name, vpn.State));
        var old = extensions[2];
        Assert.Equal((false, false, "terminated waiting to uninstall on reboot"), (old.Enabled, old.Active, old.State));
    }

    [Fact]
    public void Loaded_kexts_are_recognised_by_the_shape_of_each_row_not_by_the_header()
    {
        var withoutHeader = string.Join('\n', Fixture(Unverified, "kmutil-showloaded").Split('\n').Where(l => !l.StartsWith("Index", StringComparison.Ordinal)));

        var kexts = KextList.Parse(withoutHeader);

        Assert.Equal(["com.apple.kpi.bsd", "com.apple.iokit.IOUSBHostFamily", "com.example.driver"], kexts.Select(k => k.BundleId));
        Assert.Equal("1.0.0", kexts[2].Version);
        Assert.Empty(KextList.Parse("No variant specified, falling back to release\n"));
    }

    [Fact]
    public void Background_task_items_are_read_per_user_with_their_disposition_split_into_words()
    {
        var items = BtmDump.Parse(Fixture(Unverified, "sfltool-dumpbtm"));

        Assert.Equal(3, items.Count);
        var helper = items[0];
        Assert.Equal((0, "com.example.helper", "legacy daemon"), (helper.Uid, helper.Name, helper.Type));
        Assert.Equal("/Library/PrivilegedHelperTools/com.example.helper", helper.ExecutablePath);
        Assert.True(helper.Enabled);
        var sync = items[1];
        Assert.Equal((501, "Example Sync", false), (sync.Uid, sync.Name, sync.Enabled)); // "disallowed" is not "allowed"
        Assert.Equal(["Name", "Type", "Disposition"], items[2].Missing);
    }

    [Fact]
    public void An_item_that_is_enabled_but_disallowed_is_not_enabled()
    {
        var item = BtmDump.Parse(" #1:\n   Name: x\n   Type: agent (0x8)\n   Disposition: [enabled, disallowed, visible] (0x9)\n").Single();

        Assert.False(item.Enabled);
        Assert.Equal(["enabled", "disallowed", "visible"], item.Disposition);
        Assert.Equal("agent", item.Type);
    }

    [Fact]
    public async Task Third_party_system_extensions_and_kexts_are_listed_and_apples_kexts_hidden_by_default()
    {
        var mac = new FakeMac
        {
            SystemExtensions = FakeCommands.Ok(Fixture(Unverified, "systemextensionsctl-list")),
            Kexts = FakeCommands.Ok(Fixture(Unverified, "kmutil-showloaded")),
        };

        var result = await Audit(mac, new AutostartQuery("sysext,kext"));

        Assert.Equal(["com.example.edr.agent", "com.example.old", "com.example.vpn.extension"],
            result.Entries.Where(e => e.Category == "sysext").Select(e => e.Entry));
        Assert.Equal(["com.example.driver"], result.Entries.Where(e => e.Category == "kext").Select(e => e.Entry));
        Assert.Contains(result.Limitations, l => l.Contains("bundle identifier", StringComparison.Ordinal));

        var all = await Audit(mac, new AutostartQuery("kext", HideApple: false));
        Assert.Equal(3, all.Entries.Count);
    }

    [Fact]
    public async Task Background_task_items_need_root_and_say_so_otherwise()
    {
        var mac = new FakeMac { Btm = FakeCommands.Ok(Fixture(Unverified, "sfltool-dumpbtm")), Root = false };

        var result = await Audit(mac, new AutostartQuery("btm"));

        Assert.Empty(result.Entries);
        Assert.Contains(result.Limitations, l => l.Contains("sfltool dumpbtm", StringComparison.Ordinal) && l.Contains("root", StringComparison.Ordinal));
        Assert.DoesNotContain(mac.Commands.Calls, c => c.Program == "sfltool");
    }

    [Fact]
    public async Task Background_task_items_list_with_their_program_and_absent_keys_are_named()
    {
        var mac = new FakeMac { Btm = FakeCommands.Ok(Fixture(Unverified, "sfltool-dumpbtm")) };
        mac.Stats["/Library/PrivilegedHelperTools/com.example.helper"] = Line("/Library/PrivilegedHelperTools/com.example.helper", 0, 0, "0755", "Regular File");

        var result = await Audit(mac, new AutostartQuery("btm"));

        var helper = result.Entries.Single(e => e.Entry == "com.example.helper");
        Assert.Equal(("btm", "/Library/PrivilegedHelperTools/com.example.helper", true), (helper.Category, helper.ImagePath, helper.Enabled));
        var sync = result.Entries.Single(e => e.Entry == "Example Sync");
        Assert.Equal(("uid 501", false), (sync.Profile, sync.Enabled));
        Assert.Contains(result.Limitations, l => l.Contains("com.example.broken", StringComparison.Ordinal) && l.Contains("Disposition", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_legacy_daemon_already_listed_from_its_plist_is_not_repeated_from_background_task_management()
    {
        var mac = new FakeMac { Btm = FakeCommands.Ok(Fixture(Unverified, "sfltool-dumpbtm").Replace("/Library/PrivilegedHelperTools/com.example.helper", AgentDProgram, StringComparison.Ordinal)) };

        var result = await Audit(mac, new AutostartQuery("daemons,btm"));

        Assert.Single(result.Entries, e => e.ImagePath == AgentDProgram);
    }

    [Fact]
    public async Task A_command_that_fails_or_prints_nothing_recognisable_is_a_named_limitation_never_silent_emptiness()
    {
        var mac = new FakeMac
        {
            SystemExtensions = new ExternalResult(1, "", "systemextensionsctl: not permitted"),
            Kexts = FakeCommands.Ok("some future format nobody parses\nwith two lines\n"),
        };

        var result = await Audit(mac, new AutostartQuery("sysext,kext"));

        Assert.Empty(result.Entries);
        Assert.Contains(result.Limitations, l => l.Contains("systemextensionsctl", StringComparison.Ordinal) && l.Contains("not permitted", StringComparison.Ordinal));
        Assert.Contains(result.Limitations, l => l.Contains("kmutil", StringComparison.Ordinal) && l.Contains("recognise", StringComparison.Ordinal));
    }

    [Fact]
    public async Task No_extensions_at_all_is_an_empty_list_with_no_limitation_about_them()
    {
        var result = await Audit(new FakeMac(), new AutostartQuery("sysext,kext"));

        Assert.Empty(result.Entries);
        Assert.DoesNotContain(result.Limitations, l => l.Contains("systemextensionsctl", StringComparison.Ordinal) || l.Contains("kmutil", StringComparison.Ordinal));
    }
}
