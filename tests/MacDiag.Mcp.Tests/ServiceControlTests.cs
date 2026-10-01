using System.Collections;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Services;
using MacDiag.Mcp.Mac.Launchd;
using Microsoft.Extensions.Logging.Abstractions;
using static MacDiag.Mcp.Tests.SystemOverviewTests;

namespace MacDiag.Mcp.Tests;

public sealed class ServiceControlTests
{
    /// <summary>A launchd that remembers what is loaded: bootout unloads (after a few polls when slow), bootstrap loads.</summary>
    private sealed class Launchd
    {
        private readonly HashSet<string> _loaded;
        private int _unloadPolls;

        public Launchd(params string[] loaded) => _loaded = [.. loaded];

        public int BootoutExit { get; init; }

        public int PollsBeforeUnloaded { get; init; }

        public bool NeverUnloads { get; init; }

        public Dictionary<string, string> PlistLabels { get; } = new(StringComparer.Ordinal);

        public FakeCommands Commands => new((program, args) => (program, args.FirstOrDefault()) switch
        {
            ("launchctl", "print") => Print(args[1]),
            ("launchctl", "print-disabled") => FakeCommands.Ok(Fixture(Unverified, "launchctl-print-disabled")),
            ("launchctl", "kickstart") => FakeCommands.Ok(""),
            ("launchctl", "bootout") => Bootout(args[1]),
            ("launchctl", "bootstrap") => Bootstrap(args[2]),
            ("plutil", "-extract") => PlistLabels.TryGetValue(args[^1], out var label) ? FakeCommands.Ok(label + "\n") : new ExternalResult(1, "", "no Label"),
            _ => new ExternalResult(1, "", $"unexpected {program} {string.Join(' ', args)}"),
        });

        private ExternalResult Print(string target)
        {
            var label = target["system/".Length..];
            if (_loaded.Contains(label))
            {
                return FakeCommands.Ok($"{target} = {{\n\tstate = running\n\tpid = 4242\n\tpath = /Library/LaunchDaemons/{label}.plist\n}}\n");
            }

            if (_unloadPolls > 0)
            {
                _unloadPolls--;
                return FakeCommands.Ok($"{target} = {{\n\tstate = running\n}}\n");
            }

            return new ExternalResult(113, "", "Could not find service");
        }

        private ExternalResult Bootout(string target)
        {
            var label = target["system/".Length..];
            if (!NeverUnloads)
            {
                _loaded.Remove(label);
                _unloadPolls = PollsBeforeUnloaded;
            }

            return new ExternalResult(BootoutExit, "", BootoutExit == 36 ? "Boot-out failed: 36: Operation now in progress" : "");
        }

        private ExternalResult Bootstrap(string plist)
        {
            _loaded.Add(PlistLabels[plist]);
            return FakeCommands.Ok("");
        }
    }

    private static MacServiceController Controller(FakeCommands commands, string? ownLabel = null, params string[] plists)
    {
        var environment = new Hashtable();
        if (ownLabel is not null)
        {
            environment["MACDIAG_SERVICE_LABEL"] = ownLabel;
        }

        return new MacServiceController(commands, MacDiagOptions.FromEnvironment(environment), NullLogger<MacServiceController>.Instance)
        {
            Plists = new LaunchdPlists { FileExists = plists.Contains, ListPlists = _ => [] },
            PollDelay = TimeSpan.Zero,
            JobWait = TimeSpan.FromMilliseconds(200),
        };
    }

    [Theory]
    [InlineData("com.openssh.sshd", ServiceAction.Stop)]
    [InlineData("com.apple.WindowServer", ServiceAction.Restart)]
    [InlineData("io.tailscale.ipn.macsys", ServiceAction.Stop)]
    public async Task Stopping_or_restarting_what_keeps_the_mac_reachable_is_refused_before_anything_runs(string label, ServiceAction action)
    {
        // Review Focus 2.
        var commands = new Launchd(label).Commands;

        var ex = await Assert.ThrowsAsync<ServiceControlException>(() => Controller(commands).ControlAsync(label, action, CancellationToken.None));

        Assert.Contains("Nothing has been done", ex.Message, StringComparison.Ordinal);
        Assert.Empty(commands.Calls);
    }

    [Fact]
    public async Task This_servers_own_job_is_never_restarted_through_service_control()
    {
        var commands = new Launchd("com.corp.diag").Commands;

        var ex = await Assert.ThrowsAsync<ServiceControlException>(() =>
            Controller(commands, ownLabel: "com.corp.diag").ControlAsync("com.corp.diag", ServiceAction.Restart, CancellationToken.None));

        Assert.Contains("update_self", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Starting_a_loaded_job_kickstarts_it_and_a_protected_job_may_be_started()
    {
        var commands = new Launchd("com.apple.something").Commands;

        await Controller(commands).ControlAsync("com.apple.something", ServiceAction.Start, CancellationToken.None);

        Assert.Contains(commands.Calls, c => c.Arguments.SequenceEqual(["kickstart", "system/com.apple.something"]));
    }

    [Fact]
    public async Task Starting_an_unloaded_job_bootstraps_its_daemon_plist_and_reports_it_running()
    {
        var launchd = new Launchd();
        launchd.PlistLabels["/Library/LaunchDaemons/com.example.web.plist"] = "com.example.web";
        var commands = launchd.Commands;

        var result = await Controller(commands, null, "/Library/LaunchDaemons/com.example.web.plist")
            .ControlAsync("com.example.web", ServiceAction.Start, CancellationToken.None);

        Assert.Contains(commands.Calls, c => c.Arguments.SequenceEqual(["bootstrap", "system", "/Library/LaunchDaemons/com.example.web.plist"]));
        Assert.Equal(("not loaded", "running (PID 4242)"), (result.StatusBefore, result.StatusAfter));
    }

    [Fact]
    public async Task A_disabled_job_is_not_bootstrapped_and_the_refusal_says_how_to_enable_it()
    {
        // launchctl would answer an opaque "5: Input/output error".
        var commands = new Launchd().Commands;

        var ex = await Assert.ThrowsAsync<ServiceControlException>(() =>
            Controller(commands, null, "/Library/LaunchDaemons/com.example.old.plist").ControlAsync("com.example.old", ServiceAction.Start, CancellationToken.None));

        Assert.Contains("launchctl enable system/com.example.old", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(commands.Calls, c => c.Arguments[0] == "bootstrap");
    }

    [Fact]
    public async Task A_plist_whose_label_is_another_jobs_is_not_bootstrapped()
    {
        var launchd = new Launchd();
        launchd.PlistLabels["/Library/LaunchDaemons/com.example.web.plist"] = "com.example.other";
        var commands = launchd.Commands;

        await Assert.ThrowsAsync<ServiceControlException>(() =>
            Controller(commands, null, "/Library/LaunchDaemons/com.example.web.plist").ControlAsync("com.example.web", ServiceAction.Start, CancellationToken.None));
        Assert.DoesNotContain(commands.Calls, c => c.Arguments[0] == "bootstrap");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(36)] // "Operation now in progress": the job is still exiting
    public async Task Stopping_boots_the_job_out_and_waits_until_launchd_has_let_it_go(int bootoutExit)
    {
        var commands = new Launchd("com.example.web") { BootoutExit = bootoutExit, PollsBeforeUnloaded = 2 }.Commands;

        var result = await Controller(commands).ControlAsync("com.example.web", ServiceAction.Stop, CancellationToken.None);

        Assert.Equal("not loaded", result.StatusAfter);
    }

    [Fact]
    public async Task A_job_still_unloading_when_the_wait_ends_is_reported_as_such_not_as_an_error()
    {
        var commands = new Launchd("com.example.web") { NeverUnloads = true }.Commands;

        var result = await Controller(commands).ControlAsync("com.example.web", ServiceAction.Stop, CancellationToken.None);

        Assert.Equal("still unloading", result.StatusAfter);
    }

    [Fact]
    public async Task Restarting_kickstarts_with_kill_and_an_unloaded_job_is_told_to_use_start()
    {
        var commands = new Launchd("com.example.web").Commands;

        await Controller(commands).ControlAsync("com.example.web", ServiceAction.Restart, CancellationToken.None);
        Assert.Contains(commands.Calls, c => c.Arguments.SequenceEqual(["kickstart", "-k", "system/com.example.web"]));

        var ex = await Assert.ThrowsAsync<ServiceControlException>(() =>
            Controller(new Launchd().Commands).ControlAsync("com.example.web", ServiceAction.Restart, CancellationToken.None));
        Assert.Contains("use start", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_refused_label_never_reaches_launchctl()
    {
        var commands = new Launchd().Commands;

        await Assert.ThrowsAsync<ArgumentException>(() => Controller(commands).ControlAsync("-k", ServiceAction.Start, CancellationToken.None));
        Assert.Empty(commands.Calls);
    }
}
