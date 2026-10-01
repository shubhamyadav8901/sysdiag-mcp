using System.Collections;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Services;
using MacDiag.Mcp.Mac.Launchd;
using MacDiag.Mcp.Tools;
using static MacDiag.Mcp.Tests.SystemOverviewTests;

namespace MacDiag.Mcp.Tests;

public sealed class ServiceConfigTests
{
    private const string SshPlist = "/System/Library/LaunchDaemons/ssh.plist";

    /// <summary>launchctl and plutil answered from the fixtures; print fails for any label but sshd unless told otherwise.</summary>
    internal static FakeCommands Launchd(string? print = null, bool loaded = true, bool plistReadable = true, string console = "501") =>
        new((program, args) => (program, args.FirstOrDefault()) switch
        {
            ("launchctl", "print") when args[1] == "system/com.openssh.sshd" && loaded => FakeCommands.Ok(print ?? Fixture(Unverified, "launchctl-print-sshd")),
            ("launchctl", "print") => new ExternalResult(113, "", "Could not find service in domain for port"),
            ("launchctl", "print-disabled") => FakeCommands.Ok(Fixture(Unverified, "launchctl-print-disabled")),
            ("launchctl", "list") => FakeCommands.Ok(Fixture(Unverified, "launchctl-list")),
            ("plutil", "-convert") => plistReadable ? FakeCommands.Ok(Fixture(Unverified, "plist-sshd.xml")) : new ExternalResult(1, "", "plutil: permission denied"),
            ("plutil", "-extract") => args[^1] == SshPlist ? FakeCommands.Ok("com.openssh.sshd\n") : FakeCommands.Ok("com.other\n"),
            ("stat", _) => FakeCommands.Ok(console + "\n"),
            _ => new ExternalResult(1, "", $"unexpected {program} {string.Join(' ', args)}"),
        });

    internal static LaunchdPlists Plists(params string[] files) => new()
    {
        FileExists = path => files.Contains(path),
        ListPlists = directory => files.Where(f => f.StartsWith(directory + "/", StringComparison.Ordinal)),
    };

    private static Task<ServiceQueryResult> Query(FakeCommands commands, string label, LaunchdPlists? plists = null) =>
        new MacServiceInspector(commands, MacDiagOptions.FromEnvironment(new Hashtable())) { Plists = plists ?? Plists() }
            .QueryAsync(label, CancellationToken.None);

    [Fact]
    public async Task A_loaded_job_reads_runtime_state_from_launchctl_and_configuration_from_its_plist()
    {
        var result = await Query(Launchd(), "com.openssh.sshd");

        var service = result.Service!;
        Assert.Equal(("system", SshPlist, "not running"), (service.Domain, service.PlistPath, service.Status));
        Assert.Equal("/usr/libexec/sshd-keygen-wrapper", service.Program);
        Assert.Equal(["/usr/sbin/sshd", "-i"], service.Arguments);
        Assert.True(service.RunAtLoad);
        Assert.Equal("when: SuccessfulExit=false", service.KeepAlive);
        Assert.Equal("root", service.Account);
        Assert.False(service.Disabled);
    }

    [Fact]
    public async Task The_plists_program_wins_over_what_launchctl_prints()
    {
        // launchctl print is documented as unstable; the plist is the configuration.
        var print = Fixture(Unverified, "launchctl-print-sshd").Replace("program = /usr/libexec/sshd-keygen-wrapper", "program = /print/says/this", StringComparison.Ordinal);

        var result = await Query(Launchd(print), "com.openssh.sshd");

        Assert.Equal("/usr/libexec/sshd-keygen-wrapper", result.Service!.Program);
    }

    [Fact]
    public async Task An_unloaded_job_whose_file_is_named_otherwise_is_found_by_the_label_inside_it()
    {
        // com.openssh.sshd lives in ssh.plist: with Remote Login off it is not loaded and <label>.plist does not exist.
        var result = await Query(Launchd(loaded: false), "com.openssh.sshd", Plists("/System/Library/LaunchDaemons/other.plist", SshPlist));

        Assert.Equal(SshPlist, result.Service!.PlistPath);
        Assert.Equal("not loaded", result.Service.Status);
        Assert.Equal("system", result.Service.Domain);
    }

    [Fact]
    public async Task A_plist_search_that_stops_at_its_bound_never_answers_not_found()
    {
        var plists = new LaunchdPlists
        {
            FileExists = _ => false,
            ListPlists = directory => directory == "/System/Library/LaunchDaemons" ? ["/System/Library/LaunchDaemons/a.plist", SshPlist] : [],
            MaxScanned = 1,
        };

        var ex = await Assert.ThrowsAsync<ServiceQueryException>(() => Query(Launchd(loaded: false), "com.openssh.sshd", plists));

        Assert.Contains("may still exist", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_launch_agents_missing_print_keys_are_named_too()
    {
        var agent = "/Library/LaunchAgents/com.example.agent.plist";
        var commands = new FakeCommands((program, args) => (program, args.FirstOrDefault()) switch
        {
            ("launchctl", "print") when args[1] == "gui/501/com.example.agent" => FakeCommands.Ok("gui/501/com.example.agent = {\n\tstate = running\n}\n"),
            ("launchctl", "print") => new ExternalResult(113, "", "Could not find service"),
            ("launchctl", "print-disabled") => FakeCommands.Ok(""),
            ("plutil", "-convert") => FakeCommands.Ok(Fixture(Unverified, "plist-sshd.xml")),
            ("stat", _) => FakeCommands.Ok("501\n"),
            _ => new ExternalResult(1, "", "unexpected"),
        });

        var result = await Query(commands, "com.example.agent", Plists(agent));

        Assert.Contains(result.Service!.Limitations, l => l.Contains("path", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_print_that_fails_for_another_reason_is_an_error_not_a_job_that_is_not_loaded()
    {
        var commands = new FakeCommands((_, _) => new ExternalResult(1, "", "launchctl: internal error"));

        await Assert.ThrowsAsync<ServiceQueryException>(() => Query(commands, "com.openssh.sshd"));
    }

    [Fact]
    public async Task A_label_nothing_knows_suggests_near_matches()
    {
        var result = await Query(Launchd(), "openssh");

        Assert.Null(result.Service);
        Assert.Equal(["com.openssh.sshd"], result.Candidates);
    }

    [Fact]
    public async Task A_plist_that_cannot_be_read_is_a_limitation_not_a_failure()
    {
        var result = await Query(Launchd(plistReadable: false), "com.openssh.sshd");

        Assert.Contains(result.Service!.Limitations, l => l.Contains("permission denied", StringComparison.Ordinal));
        Assert.Equal("/usr/libexec/sshd-keygen-wrapper", result.Service.Program); // print's, as the fallback
    }

    [Fact]
    public async Task A_launch_agent_is_read_in_the_console_users_domain()
    {
        var agent = "/Library/LaunchAgents/com.example.agent.plist";
        var commands = new FakeCommands((program, args) => (program, args.FirstOrDefault()) switch
        {
            ("launchctl", "print") when args[1] == "gui/501/com.example.agent" => FakeCommands.Ok("gui/501/com.example.agent = {\n\tstate = running\n\tpid = 600\n\tpath = " + agent + "\n}\n"),
            ("launchctl", "print") => new ExternalResult(113, "", "Could not find service"),
            ("launchctl", "print-disabled") => FakeCommands.Ok(""),
            ("plutil", "-convert") => FakeCommands.Ok(Fixture(Unverified, "plist-sshd.xml").Replace("com.openssh.sshd", "com.example.agent", StringComparison.Ordinal)),
            ("stat", _) => FakeCommands.Ok("501\n"),
            _ => new ExternalResult(1, "", "unexpected"),
        });

        var result = await Query(commands, "com.example.agent", Plists(agent));

        Assert.Equal(("gui/501", "running", 600), (result.Service!.Domain, result.Service.Status, result.Service.MainProcessId));
    }

    [Fact]
    public async Task A_refused_label_never_reaches_launchctl()
    {
        // Review Focus 1.
        var commands = Launchd();

        await Assert.ThrowsAsync<ArgumentException>(() => Query(commands, "com.x\"; rm -rf /"));
        Assert.Empty(commands.Calls);
    }

    [Fact]
    public async Task The_summary_names_the_job_its_state_and_its_program()
    {
        var result = await Query(Launchd(), "com.openssh.sshd");

        var summary = ServiceTools.Render(result);

        Assert.Contains("com.openssh.sshd", summary, StringComparison.Ordinal);
        Assert.Contains("not running", summary, StringComparison.Ordinal);
        Assert.Contains(SshPlist, summary, StringComparison.Ordinal);
    }
}
