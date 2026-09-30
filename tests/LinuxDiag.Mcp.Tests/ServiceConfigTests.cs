using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Diagnostics.Services;
using LinuxDiag.Mcp.Linux.External;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Tools;

namespace LinuxDiag.Mcp.Tests;

public sealed class ServiceConfigTests
{
    private static readonly LinuxDiagOptions Options = LinuxDiagOptions.FromEnvironment(new System.Collections.Hashtable());

    // Captured from WSL Ubuntu: `systemctl show --timestamp=utc -p … cron.service` (properties come in systemd's order).
    internal const string CronShow =
        "Type=simple\nRestart=on-failure\nMainPID=175\nResult=success\nNRestarts=0\nExecMainStatus=0\n" +
        "ExecStart={ path=/usr/sbin/cron ; argv[]=/usr/sbin/cron -f -P $EXTRA_OPTS ; ignore_errors=no ; start_time=[Wed 2026-09-30 16:25:21 UTC] ; stop_time=[n/a] ; pid=175 ; code=(null) ; status=0/0 }\n" +
        "User=\nId=cron.service\nNames=cron.service\nRequires=system.slice sysinit.target\nWants=\nRequiredBy=\nWantedBy=multi-user.target\n" +
        "Description=Regular background program processing daemon\nLoadState=loaded\nActiveState=active\nSubState=running\n" +
        "FragmentPath=/usr/lib/systemd/system/cron.service\nDropInPaths=\nUnitFileState=enabled\nActiveEnterTimestamp=Wed 2026-09-30 16:25:21 UTC\n";

    [Theory]
    [InlineData("cron", "cron.service")]
    [InlineData("cron.service", "cron.service")]
    [InlineData("getty@tty1", "getty@tty1.service")]
    [InlineData("php8.3-fpm", "php8.3-fpm.service")]
    [InlineData("dbus-org.freedesktop.login1.service", "dbus-org.freedesktop.login1.service")]
    public void A_name_is_a_service_unit_with_or_without_its_suffix(string typed, string unit)
    {
        Assert.Equal(unit, ServiceNames.Normalise(typed, "name"));
    }

    [Theory]
    [InlineData("ssh*", "Glob patterns")]
    [InlineData("s[s]h", "Glob patterns")]
    [InlineData("poweroff.target", "only services")]
    [InlineData("ssh.socket", "only services")]
    [InlineData("-H", "starts with '-'")]
    public void A_pattern_another_unit_type_or_an_option_is_refused_before_systemctl_runs(string typed, string reason)
    {
        var ex = Assert.Throws<ArgumentException>(() => ServiceNames.Normalise(typed, "name"));

        Assert.Contains(reason, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_show_block_parses_whatever_order_systemd_prints_it_in_and_blocks_split_on_blank_lines()
    {
        var units = SystemctlShow.Parse(CronShow + "\nId=systemd-journald.service\nLoadState=loaded\n");

        Assert.Equal(2, units.Count);
        Assert.Equal("cron.service", units[0]["Id"]);
        Assert.Equal(["system.slice", "sysinit.target"], units[0].List("Requires"));
        Assert.Empty(units[0].List("Wants"));
        Assert.Equal("systemd-journald.service", units[1]["Id"]);
    }

    [Fact]
    public void Exec_start_keeps_a_command_line_holding_a_semicolon_and_a_program_path_holding_a_space()
    {
        var shell = SystemctlShow.Command(
            "{ path=/bin/sh ; argv[]=/bin/sh -c \"a ; b=1\" ; ignore_errors=no ; start_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }");
        var spaced = SystemctlShow.Command(
            "{ path=/opt/my app/run ; argv[]=/opt/my app/run --x ; flags= ; start_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }");

        Assert.Equal(new ExecCommand("/bin/sh", "/bin/sh -c \"a ; b=1\""), shell);
        Assert.Equal(new ExecCommand("/opt/my app/run", "/opt/my app/run --x"), spaced);
    }

    [Fact]
    public async Task Near_matches_leave_out_units_systemd_only_knows_as_missing()
    {
        var commands = new FakeCommands((_, arguments) => arguments[0] switch
        {
            "show" => FakeCommands.Ok("Id=crond.service\nLoadState=not-found\n"),
            "list-units" => FakeCommands.Ok("cronie.service not-found inactive dead cronie.service\ncron.service loaded active running Cron\n"),
            "list-unit-files" => FakeCommands.Ok(""),
            _ => throw new InvalidOperationException(string.Join(' ', arguments)),
        });

        var result = await new LinuxServiceInspector(commands, Options).QueryAsync("cron", CancellationToken.None);

        Assert.Equal(["cron.service (Cron)"], result.Candidates);
    }

    [Fact]
    public void Exec_start_gives_the_program_and_its_command_line_and_timestamps_are_utc()
    {
        var command = SystemctlShow.Command(
            "{ path=/usr/sbin/cron ; argv[]=/usr/sbin/cron -f -P $EXTRA_OPTS ; ignore_errors=no ; start_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }");

        Assert.Equal(new ExecCommand("/usr/sbin/cron", "/usr/sbin/cron -f -P $EXTRA_OPTS"), command);
        Assert.Equal(new DateTimeOffset(2026, 9, 30, 16, 25, 21, TimeSpan.Zero), SystemctlShow.Timestamp("Wed 2026-09-30 16:25:21 UTC"));
        Assert.Null(SystemctlShow.Timestamp(""));
        Assert.Null(SystemctlShow.Timestamp("n/a"));
        Assert.Null(SystemctlShow.Command("garbage"));
    }

    [Fact]
    public void A_unit_becomes_windiags_service_shape_with_linuxs_extra_facts()
    {
        var info = LinuxServiceInspector.ToInfo(SystemctlShow.Parse(CronShow)[0]);

        Assert.Equal("cron.service", info.ServiceName);
        Assert.Equal("Regular background program processing daemon", info.DisplayName);
        Assert.Equal("active (running)", info.Status);
        Assert.Equal("enabled", info.StartType);
        Assert.Equal("simple", info.ServiceType);
        Assert.Equal("/usr/sbin/cron -f -P $EXTRA_OPTS", info.ImagePath);
        Assert.Equal("root", info.Account);
        Assert.Equal(175, info.MainProcessId);
        Assert.Equal(["system.slice", "sysinit.target"], info.DependsOn);
        Assert.Empty(info.DependedOnBy);
        Assert.Equal(["multi-user.target"], info.WantedBy);
    }

    [Fact]
    public void Only_the_units_a_stop_takes_down_count_as_dependents_and_wanting_is_reported_apart()
    {
        // Stopping a unit stops what Requires, Requisite, BindsTo or PartOf it -- not what merely Wants it.
        var info = LinuxServiceInspector.ToInfo(SystemctlShow.Parse(
            "Id=db.service\nRequires=a.service\nBindsTo=b.device\nRequisite=c.service\nWants=d.service\n" +
            "RequiredBy=app.service\nBoundBy=sidecar.service\nRequisiteOf=check.service\nConsistsOf=worker.service\n" +
            "WantedBy=multi-user.target\nLoadState=loaded\nActiveState=active\nSubState=running\n")[0]);

        Assert.Equal(["a.service", "b.device", "c.service"], info.DependsOn);
        Assert.Equal(["d.service"], info.WeakDependsOn);
        Assert.Equal(["app.service", "sidecar.service", "check.service", "worker.service"], info.DependedOnBy);
        Assert.Equal(["multi-user.target"], info.WantedBy);
    }

    [Fact]
    public void A_dynamic_user_service_is_not_reported_as_running_as_root()
    {
        var info = LinuxServiceInspector.ToInfo(SystemctlShow.Parse(
            CronShow.Replace("User=\n", "User=\nDynamicUser=yes\n", StringComparison.Ordinal))[0]);

        Assert.Equal("dynamic user (cron)", info.Account);
    }

    [Fact]
    public void Enabled_but_stopped_and_masked_each_get_their_note()
    {
        var stopped = LinuxServiceInspector.ToInfo(SystemctlShow.Parse(
            CronShow.Replace("ActiveState=active", "ActiveState=failed", StringComparison.Ordinal)
                    .Replace("SubState=running", "SubState=failed", StringComparison.Ordinal)
                    .Replace("Result=success", "Result=exit-code", StringComparison.Ordinal))[0]);
        var masked = LinuxServiceInspector.ToInfo(SystemctlShow.Parse(
            CronShow.Replace("UnitFileState=enabled", "UnitFileState=masked", StringComparison.Ordinal))[0]);

        Assert.Contains("enabled to start at boot but is currently failed", ServiceTools.Render(new ServiceQueryResult("cron", stopped, [])), StringComparison.Ordinal);
        Assert.Contains("exit-code", ServiceTools.Render(new ServiceQueryResult("cron", stopped, [])), StringComparison.Ordinal);
        Assert.Contains("MASKED", ServiceTools.Render(new ServiceQueryResult("cron", masked, [])), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_name_systemd_does_not_know_lists_near_matches_by_name_or_description()
    {
        var commands = new FakeCommands((_, arguments) => arguments[0] switch
        {
            "show" => FakeCommands.Ok("Id=crond.service\nLoadState=not-found\n"),
            "list-units" => FakeCommands.Ok("cron.service loaded active running Regular background program processing daemon\n"),
            "list-unit-files" => FakeCommands.Ok("cron.service enabled enabled\nanacron.service enabled enabled\nssh.service disabled enabled\n"),
            _ => throw new InvalidOperationException(string.Join(' ', arguments)),
        });

        var result = await new LinuxServiceInspector(commands, Options).QueryAsync("cron", CancellationToken.None);

        Assert.Null(result.Service);
        Assert.Equal(["anacron.service", "cron.service (Regular background program processing daemon)"], result.Candidates);
        Assert.Contains(commands.Calls, c => c.Arguments.SequenceEqual(new[] { "show", "--timestamp=utc", "-p", string.Join(',', LinuxServiceInspector.Properties), "--", "cron.service" }));
    }

    [Fact]
    public void Every_captured_distro_parses()
    {
        foreach (var distro in ProcParserTests.Distros())
        {
            var units = SystemctlShow.Parse(ProcParserTests.Fixture(distro, "systemctl-show")!);
            var journald = Assert.Single(units, u => u["Id"] == "systemd-journald.service");
            Assert.Equal("loaded", journald["LoadState"]);
            Assert.NotNull(LinuxServiceInspector.ToInfo(journald).ImagePath);
        }
    }

    [LinuxFact]
    public async Task The_live_journal_service_is_described()
    {
        var result = await new LinuxServiceInspector(new LinuxExternalCommand(), Options)
            .QueryAsync("systemd-journald", CancellationToken.None);

        Assert.Equal("systemd-journald.service", result.Service?.ServiceName);
        Assert.Equal("loaded", result.Service?.LoadState);
    }
}
