using LinuxDiag.Mcp.Diagnostics.Services;
using LinuxDiag.Mcp.Linux.External;
using LinuxDiag.Mcp.Tools;
using Microsoft.Extensions.Logging.Abstractions;

namespace LinuxDiag.Mcp.Tests;

/// <summary>The controller against a scripted systemctl: test-linux runs unprivileged, and so cannot start units.</summary>
public sealed class ServiceControlTests
{
    private static string Show(string id, string state, string names = "", string extra = "") =>
        $"Id={id}\nNames={(names.Length == 0 ? id : names)}\nDescription=Test {id}\nLoadState=loaded\nActiveState={state}\nSubState={(state == "active" ? "running" : "dead")}\n{extra}";

    /// <summary>A systemctl whose unit goes from <paramref name="before"/> to <paramref name="after"/> when acted on.</summary>
    private sealed class Scripted
    {
        public string Before { get; init; } = "active";
        public string After { get; init; } = "inactive";
        public string Names { get; init; } = "";
        public string? Id { get; init; }
        public string Extra { get; init; } = "";
        public string Dependents { get; init; } = "";
        /// <summary>Replaces list-dependencies' whole answer, for a run that fails.</summary>
        public ExternalResult? DependentsResult { get; init; }
        public ExternalResult Action { get; init; } = FakeCommands.Ok("");
        public bool TimesOut { get; init; }
        public List<IReadOnlyList<string>> Calls { get; } = [];
        private bool _acted;

        public FakeCommands Commands => new((_, arguments) =>
        {
            Calls.Add(arguments);
            if (arguments.Contains("list-dependencies"))
            {
                return DependentsResult ?? FakeCommands.Ok(Dependents);
            }

            if (arguments[0] == "show")
            {
                var units = arguments.SkipWhile(a => a != "--").Skip(1).ToList();
                return FakeCommands.Ok(string.Join("\n", units.Select(u =>
                    u == "worker.service" ? Show(u, _acted ? "inactive" : "active") : Show(Id ?? u, _acted ? After : Before, Names, Extra))));
            }

            if (TimesOut)
            {
                throw new ExternalCommandException("systemctl did not finish within 75 s and was stopped.", timedOut: true);
            }

            _acted = true;
            return Action;
        });
    }

    private static LinuxServiceController Controller(IExternalCommand commands, string? self = null) =>
        new(commands, NullLogger<LinuxServiceController>.Instance) { SelfUnit = () => self };

    [Fact]
    public async Task A_critical_service_is_refused_by_any_of_its_names_and_nothing_is_run()
    {
        // A unit answers to every name in Names= (Debian's sshd.service is an alias of ssh.service). Asked by
        // an alias that is on no list, the refusal must still see the critical name behind it.
        var script = new Scripted { Names = "ssh.service ssh-alias.service" };

        var ex = await Assert.ThrowsAsync<ServiceControlException>(() =>
            Controller(script.Commands).ControlAsync("ssh-alias", ServiceAction.Stop, CancellationToken.None));

        Assert.Contains("Refusing to stop", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(script.Calls, c => c.Contains("stop"));
    }

    [Fact]
    public async Task A_service_that_powers_the_machine_off_is_refused_even_to_start()
    {
        // Review Focus 1: systemd-poweroff.service is a service, and starting it is a power-off.
        var script = new Scripted
        {
            Before = "inactive",
            Extra = "SuccessAction=poweroff-force\nFailureAction=none\nRequires=shutdown.target umount.target final.target\n",
        };

        var ex = await Assert.ThrowsAsync<ServiceControlException>(() =>
            Controller(script.Commands).ControlAsync("systemd-poweroff", ServiceAction.Start, CancellationToken.None));

        Assert.Contains("shuts down, reboots or suspends", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(script.Calls, c => c.Contains("start"));
    }

    [Fact]
    public async Task A_service_asked_for_by_an_alias_reports_its_state_after_the_action()
    {
        // Final review: systemctl show prints the primary name as Id (mysql -> mariadb.service), so matching the
        // after-state on the requested name fell back to the before-state and reported a stop as still running.
        var script = new Scripted { Id = "mariadb.service", Names = "mariadb.service mysql.service" };

        var result = await Controller(script.Commands).ControlAsync("mysql", ServiceAction.Stop, CancellationToken.None);

        Assert.Equal("inactive (dead)", result.StatusAfter);
    }

    [Fact]
    public async Task Dependents_are_listed_in_full_so_a_long_unit_name_is_never_shortened()
    {
        var script = new Scripted();

        await Controller(script.Commands).ControlAsync("app", ServiceAction.Stop, CancellationToken.None);

        Assert.Contains(script.Calls, c => c.Contains("list-dependencies") && c.Contains("--full"));
    }

    [Fact]
    public async Task A_stop_that_would_take_a_critical_service_down_with_it_is_refused()
    {
        var script = new Scripted { Dependents = "app.service\n  ssh.service\n" };

        var ex = await Assert.ThrowsAsync<ServiceControlException>(() =>
            Controller(script.Commands).ControlAsync("app", ServiceAction.Stop, CancellationToken.None));

        Assert.Contains("would also stop ssh.service", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(script.Calls, c => c.Contains("stop"));
    }

    [Theory]
    [InlineData(ServiceAction.Stop)]
    [InlineData(ServiceAction.Restart)]
    public async Task A_stop_whose_dependents_cannot_be_listed_is_refused_rather_than_run_blind(ServiceAction action)
    {
        // list-dependencies can exit non-zero with empty or partial output - a D-Bus timeout on a loaded machine,
        // or one unit's properties failing part-way through the --all walk. Read as "no dependents", that let a
        // stop through that took ssh.service or this server down with it: an unknown list cannot be shown to be
        // free of critical units.
        var script = new Scripted
        {
            DependentsResult = new ExternalResult(1, "", "Failed to get properties: Connection timed out\n"),
        };

        var ex = await Assert.ThrowsAsync<ServiceControlException>(() =>
            Controller(script.Commands, self: "linuxdiag.service").ControlAsync("app", action, CancellationToken.None));

        Assert.Contains("could not list the services that depend on it", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Connection timed out", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Nothing has been done", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(script.Calls, c => c.Contains("stop") || c.Contains("restart"));
    }

    [Theory]
    [InlineData("tailscaled")]
    [InlineData("wg-quick@wg0")]
    [InlineData("openvpn@office")]
    public async Task A_vpn_or_tunnel_the_machine_may_be_reached_through_is_critical(string name)
    {
        var script = new Scripted();

        await Assert.ThrowsAsync<ServiceControlException>(() =>
            Controller(script.Commands).ControlAsync(name, ServiceAction.Stop, CancellationToken.None));
    }

    [Fact]
    public async Task Starting_a_critical_service_is_allowed()
    {
        var script = new Scripted { Before = "inactive", After = "active", Names = "ssh.service sshd.service" };

        var result = await Controller(script.Commands).ControlAsync("ssh", ServiceAction.Start, CancellationToken.None);

        Assert.Equal("active (running)", result.StatusAfter);
        Assert.Contains(script.Calls, c => c.SequenceEqual(new[] { "--no-ask-password", "start", "--", "ssh.service" }));
    }

    [Fact]
    public async Task This_servers_own_service_and_anything_it_depends_on_cannot_be_stopped()
    {
        var own = await Assert.ThrowsAsync<ServiceControlException>(() =>
            Controller(new Scripted().Commands, self: "linuxdiag.service").ControlAsync("linuxdiag", ServiceAction.Restart, CancellationToken.None));
        var dependency = await Assert.ThrowsAsync<ServiceControlException>(() =>
            Controller(new Scripted { Dependents = "network-online.target\n  linuxdiag.service\n" }.Commands, self: "linuxdiag.service")
                .ControlAsync("network-online", ServiceAction.Stop, CancellationToken.None));

        Assert.Contains("update_self", own.Message, StringComparison.Ordinal);
        Assert.Contains("would also stop this diagnostics server", dependency.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Dependents_that_stopped_with_it_are_recorded_because_a_restart_does_not_bring_them_back()
    {
        var script = new Scripted { Dependents = "app.service\n  worker.service\n" };

        var result = await Controller(script.Commands).ControlAsync("app", ServiceAction.Stop, CancellationToken.None);

        Assert.Equal(["worker.service"], result.DependentServicesStopped);
        Assert.Contains("does NOT bring back", result.Detail, StringComparison.Ordinal);
        Assert.Contains("active (running) -> inactive (dead)", result.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_job_still_running_past_the_bound_is_reported_as_still_running_not_as_failed()
    {
        var result = await Controller(new Scripted { TimesOut = true, After = "active" }.Commands)
            .ControlAsync("app", ServiceAction.Restart, CancellationToken.None);

        Assert.Contains("did not finish within 75 s", result.Detail, StringComparison.Ordinal);
        Assert.Contains("systemd keeps running it", result.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_refusal_from_systemctl_is_reported_with_its_reason_and_a_start_that_did_not_take_says_where_to_look()
    {
        var denied = await Assert.ThrowsAsync<ServiceControlException>(() =>
            Controller(new Scripted { Action = new ExternalResult(4, "", "Failed to stop app.service: Access denied\n") }.Commands)
                .ControlAsync("app", ServiceAction.Stop, CancellationToken.None));
        var failed = await Controller(new Scripted { Before = "inactive", After = "failed" }.Commands)
            .ControlAsync("app", ServiceAction.Start, CancellationToken.None);

        Assert.Contains("Access denied", denied.Message, StringComparison.Ordinal);
        Assert.Contains("event_log_tail with unit='app.service'", failed.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_service_that_does_not_exist_is_refused()
    {
        var commands = new FakeCommands((_, _) => FakeCommands.Ok("Id=nope.service\nNames=nope.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n"));

        var ex = await Assert.ThrowsAsync<ServiceControlException>(() =>
            Controller(commands).ControlAsync("nope", ServiceAction.Start, CancellationToken.None));

        Assert.Contains("No service named", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("start", ServiceAction.Start)]
    [InlineData(" Stop ", ServiceAction.Stop)]
    [InlineData("restart", ServiceAction.Restart)]
    [InlineData("bounce", ServiceAction.Restart)]
    public void Actions_keep_windiags_names(string text, ServiceAction action)
    {
        Assert.Equal(action, ControlTools.ParseServiceAction(text));
        Assert.Throws<ArgumentException>(() => ControlTools.ParseServiceAction("reload"));
    }

    [Fact]
    public void A_read_only_server_does_not_register_service_control()
    {
        using var readOnly = ToolRegistrationTests.Provider(ToolRegistrationTests.Options(readOnly: true));

        Assert.DoesNotContain(
            Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions
                .GetServices<ModelContextProtocol.Server.McpServerTool>(readOnly).Select(t => t.ProtocolTool.Name),
            n => n == "service_control");
    }
}
