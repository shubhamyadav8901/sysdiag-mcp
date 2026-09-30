using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Diagnostics;
using LinuxDiag.Mcp.Diagnostics.Autostart;
using LinuxDiag.Mcp.Linux.External;
using LinuxDiag.Mcp.Linux.Packages;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Tools;

namespace LinuxDiag.Mcp.Tests;

public sealed class AutostartTests
{
    private static readonly LinuxDiagOptions Options = LinuxDiagOptions.FromEnvironment(new System.Collections.Hashtable());

    [Fact]
    public void A_unit_a_systemd_generator_wrote_at_boot_is_not_a_package_finding()
    {
        // Generators write units under /run/systemd/generator* on every boot; no package ever owns those files,
        // so calling them unpackaged buried the real findings.
        var entry = new AutostartEntry("services", "/run/systemd/generator/wslg.service", "wslg.service", true, null, null,
            "/bin/mount", null, null, ["/run/systemd/generator.late/wslg.service.d/x.conf"], null, null, [], false);

        var verified = LinuxAutostartInspector.Verify(entry, path => path == "/bin/mount" ? new PackageFile("mount", "2.39", "m", false, null) : null, path => "m");

        Assert.True(verified.Packaged, string.Join("; ", verified.PackageFindings));
    }

    [Fact]
    public void A_system_crontab_gives_schedule_user_and_command_and_skips_comments_and_variables()
    {
        // Captured from WSL Ubuntu's /etc/crontab, plus an @reboot line and a user-format line.
        var system = CronTab.Parse(
            "SHELL=/bin/sh\n# m h dom mon dow user command\n" +
            "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n" +
            "@reboot root /usr/local/bin/at-boot --now\n", systemFormat: true);
        var user = CronTab.Parse("*/5 * * * * /home/me/bin/poll.sh  --quiet\n", systemFormat: false);

        Assert.Equal(new CronEntry("17 * * * *", "root", "cd / && run-parts --report /etc/cron.hourly"), system[0]);
        Assert.Equal(new CronEntry("@reboot", "root", "/usr/local/bin/at-boot --now"), system[1]);
        Assert.Equal(new CronEntry("*/5 * * * *", null, "/home/me/bin/poll.sh  --quiet"), Assert.Single(user));
    }

    [Theory]
    [InlineData("/usr/sbin/cron -f -P $EXTRA_OPTS", "/usr/sbin/cron", null)]
    [InlineData("SERVICE_MODE=1 /sbin/e2scrub_all -A -r", "/sbin/e2scrub_all", null)]
    [InlineData("/bin/sh -e /opt/vendor/start.sh --daemon", "/bin/sh", "/opt/vendor/start.sh")]
    [InlineData("/usr/bin/python3 -u /srv/app/worker.py", "/usr/bin/python3", "/srv/app/worker.py")]
    public void A_command_names_its_program_and_the_script_an_interpreter_runs(string command, string program, string? script)
    {
        Assert.Equal((program, script), LaunchCommand.Split(command));
    }

    [Fact]
    public void Categories_are_named_or_all_and_an_unknown_one_is_refused()
    {
        Assert.Equal(LinuxAutostartInspector.AllCategories, LinuxAutostartInspector.ParseCategories("all"));
        Assert.Equal(["cron", "services"], LinuxAutostartInspector.ParseCategories("services, cron"));
        Assert.Throws<ArgumentException>(() => LinuxAutostartInspector.ParseCategories("registry"));
    }

    [Fact]
    public void A_packaged_unit_with_a_foreign_drop_in_is_not_packaged_and_is_never_hidden()
    {
        // Review Focus 4: the unit and its program match their packages; the drop-in that overrides ExecStart does not.
        var entry = new AutostartEntry("services", "/usr/lib/systemd/system/cron.service", "cron.service", true, null, "cron",
            "/usr/sbin/cron", "/usr/sbin/cron -f", null, ["/etc/systemd/system/cron.service.d/override.conf"], null, null, [], false);
        var owners = new Dictionary<string, PackageFile>
        {
            ["/usr/lib/systemd/system/cron.service"] = new("cron", "3.0", "unit", false, null),
            ["/usr/sbin/cron"] = new("cron", "3.0", "binary", false, null),
        };
        var hashes = new Dictionary<string, string>
        {
            ["/usr/lib/systemd/system/cron.service"] = "unit",
            ["/usr/sbin/cron"] = "binary",
            ["/etc/systemd/system/cron.service.d/override.conf"] = "anything",
        };

        var verified = LinuxAutostartInspector.Verify(entry, path => owners.GetValueOrDefault(path), path => hashes[path]);

        Assert.False(verified.Packaged);
        Assert.Equal("cron", verified.Package);
        Assert.Contains(verified.PackageFindings, f => f.Contains("override.conf", StringComparison.Ordinal) && f.Contains("no installed package", StringComparison.OrdinalIgnoreCase));
        Assert.False(LinuxAutostartInspector.Hidden(verified, new AutostartQuery(HidePackaged: true)));
        Assert.True(LinuxAutostartInspector.Hidden(verified with { Packaged = true, PackageFindings = [] }, new AutostartQuery(HidePackaged: true)));
    }

    [Fact]
    public async Task Enabled_units_are_matched_to_their_show_blocks_by_id_and_a_timer_names_what_it_runs()
    {
        var commands = new FakeCommands((_, arguments) => arguments[0] switch
        {
            "list-unit-files" => FakeCommands.Ok("cron.service enabled enabled\nbackup.timer enabled enabled\n"),
            "show" when arguments.Contains("backup.service") => FakeCommands.Ok(
                "Id=backup.service\nDescription=Backup\nFragmentPath=/etc/systemd/system/backup.service\nDropInPaths=\n" +
                "ExecStart={ path=/usr/local/bin/backup ; argv[]=/usr/local/bin/backup --all ; ignore_errors=no ; pid=0 }\nTriggers=\nUser=\n"),
            "show" => FakeCommands.Ok(
                "Id=backup.timer\nDescription=Nightly backup\nFragmentPath=/etc/systemd/system/backup.timer\nDropInPaths=\nExecStart=\nTriggers=backup.service\nUser=\n\n" +
                "Id=cron.service\nDescription=cron\nFragmentPath=/usr/lib/systemd/system/cron.service\nDropInPaths=\n" +
                "ExecStart={ path=/usr/sbin/cron ; argv[]=/usr/sbin/cron -f ; ignore_errors=no ; pid=1 }\nTriggers=\nUser=\n"),
            _ => throw new InvalidOperationException(string.Join(' ', arguments)),
        });

        var entries = await LinuxAutostartInspector.SystemdAsync(commands, ["services", "timers"], TimeSpan.FromSeconds(5), CancellationToken.None);

        Assert.Equal("/usr/sbin/cron", entries.Single(e => e.Entry == "cron.service").ImagePath);
        var timer = entries.Single(e => e.Entry == "backup.timer");
        Assert.Equal("timers", timer.Category);
        Assert.Equal("/usr/local/bin/backup", timer.ImagePath);
        Assert.Contains("runs backup.service", timer.Description, StringComparison.Ordinal);
        Assert.Contains("/etc/systemd/system/backup.service", timer.DropIns);
    }

    [Fact]
    public async Task A_template_is_never_shown_and_its_loaded_instances_are_listed_instead()
    {
        // systemctl show getty@.service fails, and one failure fails the whole batch.
        var commands = new FakeCommands((_, arguments) => arguments[0] switch
        {
            "list-unit-files" => FakeCommands.Ok("getty@.service enabled enabled\ncron.service enabled enabled\n"),
            "list-units" => FakeCommands.Ok("getty@tty1.service loaded active running Getty on tty1\nmodprobe@drm.service loaded inactive dead Load drm\n"),
            "show" when arguments.Any(a => a.Contains("@.", StringComparison.Ordinal)) => new ExternalResult(1, "", "Unit name getty@.service is not valid."),
            "show" => FakeCommands.Ok(string.Join("\n", arguments.SkipWhile(a => a != "--").Skip(1).Select(u =>
                $"Id={u}\nDescription={u}\nFragmentPath=/usr/lib/systemd/system/{u}\nDropInPaths=\nExecStart=\nTriggers=\nUser=\n"))),
            _ => throw new InvalidOperationException(string.Join(' ', arguments)),
        });

        var entries = await LinuxAutostartInspector.SystemdAsync(commands, ["services"], TimeSpan.FromSeconds(5), CancellationToken.None);

        Assert.Equal(["cron.service", "getty@tty1.service"], entries.Select(e => e.Entry).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void The_summary_calls_out_preloads_missing_files_and_unpackaged_entries()
    {
        var entries = new List<AutostartEntry>
        {
            new("preload", "/etc/ld.so.preload", "/usr/lib/libevil.so", true, null, "loaded into every dynamically linked program",
                "/usr/lib/libevil.so", null, null, [], null, false, ["/usr/lib/libevil.so: No installed package owns this file."], true),
        };

        var summary = AutostartTools.Render(new AutostartAuditResult(entries, 1, false, true, true, 1, 1, []), "all", null);

        Assert.Contains("ATTENTION", summary, StringComparison.Ordinal);
        Assert.Contains("[FILE NOT FOUND]", summary, StringComparison.Ordinal);
        Assert.Contains("[NOT FROM A PACKAGE]", summary, StringComparison.Ordinal);
    }

    [LinuxFact]
    public void A_fifo_or_a_device_named_by_configuration_is_never_opened()
    {
        // Final review, Critical: a user's *.wants link to a FIFO blocked the root server forever, and one to
        // /dev/zero read until it ran out of memory. Configuration is opened only when it is a regular file.
        var directory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld-fifo-{Guid.NewGuid():N}")).FullName;
        var fifo = Path.Combine(directory, "p");
        LockParserTests.Run("mkfifo", fifo);

        var read = Task.Run(() => LinuxAutostartInspector.ReadConfiguration(fifo));
        Assert.True(read.Wait(TimeSpan.FromSeconds(5)), "reading a FIFO named by configuration blocked");
        Assert.Equal(string.Empty, read.Result);

        var hash = Task.Run(() => FileHashes.Compute(fifo));
        Assert.True(((IAsyncResult)hash).AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5)), "hashing a FIFO blocked");
        Assert.IsAssignableFrom<IOException>(hash.Exception?.InnerException);

        Assert.Equal(string.Empty, LinuxAutostartInspector.ReadConfiguration("/dev/zero"));
        Directory.Delete(directory, recursive: true);
    }

    [LinuxFact]
    public void A_symlink_loop_in_a_users_wants_directory_is_reported_not_fatal()
    {
        // Final review: one self-referencing link made the whole default audit fail.
        var directory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld-loop-{Guid.NewGuid():N}")).FullName;
        try
        {
            var link = Path.Combine(directory, "loop.service");
            File.CreateSymbolicLink(link, link);

            var entry = LinuxAutostartInspector.UserUnitEntry(link, "someone", lingering: false);

            Assert.Equal("loop.service", entry.Entry);
            Assert.Null(entry.ImagePath);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void A_packaged_program_with_a_file_that_does_not_match_is_named_and_not_called_unpackaged()
    {
        // Final review: a trojaned /usr/sbin/cron or a foreign drop-in was tagged "not from a package".
        var entry = new AutostartEntry("services", "/usr/lib/systemd/system/cron.service", "cron.service", true, null, "cron",
            "/usr/sbin/cron", null, null, [], "cron", false, ["/usr/sbin/cron: Does NOT match the dpkg database for cron 3.0."], false);

        var summary = AutostartTools.Render(new AutostartAuditResult([entry], 1, false, true, true, 1, 0, []), "all", null);

        Assert.Contains("cron  [FILES DO NOT MATCH THE PACKAGE]", summary, StringComparison.Ordinal);
        Assert.DoesNotContain("NOT FROM A PACKAGE", summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Without_a_dpkg_database_nothing_is_hidden_and_packages_are_not_claimed_checked()
    {
        // Final review: with no database, unpackagedOnly hid every entry and the summary said all matched.
        var unchecked_ = new AutostartEntry("preload", "/etc/ld.so.preload", "/x.so", true, null, null, "/x.so", null, null, [], null, null, [], false);
        var inspector = new LinuxAutostartInspector(
            new FakeCommands((_, arguments) => throw new InvalidOperationException(string.Join(' ', arguments))),
            new NoDatabase(), new LinuxPrivilegeProbe(), Options);

        var result = await inspector.AuditAsync(new AutostartQuery("preload", UnpackagedOnly: true), CancellationToken.None);

        Assert.False(LinuxAutostartInspector.Hidden(unchecked_, new AutostartQuery(UnpackagedOnly: true)));
        Assert.False(result.PackagesVerified);
    }

    private sealed class NoDatabase : IPackageDatabaseSource
    {
        public IPackageDatabase Open() => new Empty();

        private sealed class Empty : IPackageDatabase
        {
            public bool Available => false;

            public PackageFile? Owner(string path) => null;
        }
    }

    [LinuxFact]
    public void A_packaged_program_reached_through_a_symlink_is_judged_by_the_file_it_leads_to()
    {
        // dpkg records a symlink without a checksum, so judging the link itself called /usr/bin/python3 (a link
        // to python3.12) "not from a package". Found live, auditing WSL Ubuntu.
        var directory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld-autostart-{Guid.NewGuid():N}")).FullName;
        try
        {
            var link = Path.Combine(directory, "sleep-link");
            File.CreateSymbolicLink(link, "/usr/bin/sleep");
            var database = new DpkgDatabaseSource().Open();
            var entry = new AutostartEntry("services", "/usr/bin/sleep", "x.service", true, null, null, link, link, null, [], null, null, [], false);

            var verified = LinuxAutostartInspector.Verify(
                entry, path => LinuxAutostartInspector.PackageOwner(database, path), path => FileHashes.Compute(path).Md5);

            Assert.True(verified.Packaged, string.Join("; ", verified.PackageFindings));
            Assert.Equal("coreutils", verified.Package);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [LinuxFact]
    public async Task The_live_audit_finds_the_cron_service_and_a_cron_d_entry_and_verifies_their_packages()
    {
        var result = await new LinuxAutostartInspector(new LinuxExternalCommand(), new DpkgDatabaseSource(), new LinuxPrivilegeProbe(), Options)
            .AuditAsync(new AutostartQuery("services,cron", "cron", VerifyPackages: true), CancellationToken.None);

        var service = Assert.Single(result.Entries, e => e.Entry == "cron.service");
        Assert.Equal("/usr/sbin/cron", service.ImagePath);
        Assert.True(service.Packaged);
        Assert.Contains(result.Entries, e => e.Category == "cron" && e.Location.StartsWith("/etc/cron", StringComparison.Ordinal));
    }
}
