using LinuxDiag.Mcp.Hosting;

namespace LinuxDiag.Mcp.Tests;

public sealed class InstallTests
{
    [Fact]
    public void Install_needs_a_bind_address()
    {
        var ex = Assert.Throws<ConfigurationException>(() => LinuxServiceInstallOptions.Parse(["--install-service"]));

        Assert.Contains("--http", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_token_is_generated_when_none_is_given()
    {
        var options = LinuxServiceInstallOptions.Parse(["--install-service", "--http", "http://0.0.0.0:4024"]);

        Assert.Equal(64, options.Token.Length);
        Assert.False(options.TokenWasSupplied);
    }

    [Fact]
    public void A_token_can_arrive_on_stdin_instead_of_the_command_line()
    {
        // A value on the command line is logged by sudo and visible in ps; stdin is neither.
        var options = LinuxServiceInstallOptions.Parse(
            ["--install-service", "--http", "http://0.0.0.0:4024", "--token-stdin"], new StringReader("  t0k  \nignored\n"));

        Assert.Equal("t0k", options.Token);
        Assert.True(options.TokenWasSupplied);
    }

    [Fact]
    public void An_empty_token_on_stdin_is_refused()
    {
        Assert.Throws<ConfigurationException>(() => LinuxServiceInstallOptions.Parse(
            ["--install-service", "--http", "http://0.0.0.0:4024", "--token-stdin"], new StringReader("\n")));
    }

    [Fact]
    public void A_token_on_both_stdin_and_the_command_line_is_refused_rather_than_one_silently_winning()
    {
        var ex = Assert.Throws<ConfigurationException>(() => LinuxServiceInstallOptions.Parse(
            ["--install-service", "--http", "http://0.0.0.0:4024", "--token-stdin", "--token", "other"],
            new StringReader("t0k\n")));

        Assert.Contains("--token-stdin", ex.Message, StringComparison.Ordinal);

        // A trailing bare --token carries no value, and is still a second, conflicting instruction.
        Assert.Throws<ConfigurationException>(() => LinuxServiceInstallOptions.Parse(
            ["--install-service", "--http", "http://0.0.0.0:4024", "--token-stdin", "--token"],
            new StringReader("t0k\n")));
    }

    [Fact]
    public void The_env_file_carries_the_token_bind_service_name_and_only_granted_grants()
    {
        var options = LinuxServiceInstallOptions.Parse(
            ["--install-service", "--http", "http://0.0.0.0:4024", "--token", "t0k", "--allow-self-update"]);
        var env = options.EnvironmentFile();

        Assert.Contains("LINUXDIAG_TOKEN=t0k\n", env, StringComparison.Ordinal);
        Assert.Contains("LINUXDIAG_HTTP_BIND=http://0.0.0.0:4024\n", env, StringComparison.Ordinal);
        Assert.Contains("LINUXDIAG_SERVICE_NAME=linuxdiag\n", env, StringComparison.Ordinal);
        Assert.Contains("LINUXDIAG_ALLOW_SELF_UPDATE=1\n", env, StringComparison.Ordinal);
        Assert.DoesNotContain("COMMAND_EXECUTION", env, StringComparison.Ordinal);
        Assert.Equal("/etc/linuxdiag/linuxdiag.env", options.EnvironmentFilePath);
    }

    [Fact]
    public void The_unit_is_notify_type_restarts_on_failure_and_is_not_sandboxed()
    {
        var options = LinuxServiceInstallOptions.Parse(["--install-service", "--http", "http://0.0.0.0:4024"]);
        var unit = options.UnitFile("/opt/linuxdiag/LinuxDiag.Mcp");

        Assert.Contains("Type=notify", unit, StringComparison.Ordinal);
        Assert.Contains("ExecStart=/opt/linuxdiag/LinuxDiag.Mcp\n", unit, StringComparison.Ordinal);
        Assert.Contains("EnvironmentFile=/etc/linuxdiag/linuxdiag.env", unit, StringComparison.Ordinal);
        Assert.Contains("Restart=on-failure", unit, StringComparison.Ordinal);
        Assert.DoesNotContain("ProtectSystem", unit, StringComparison.Ordinal);
        Assert.Equal("/etc/systemd/system/linuxdiag.service", options.UnitFilePath);
    }

    [Theory]
    [InlineData(null, "/var/lib/linuxdiag")]
    [InlineData("/srv/ld", "/srv/ld")]
    public void The_unit_points_the_host_at_nothing_put_file_can_write(string? artifacts, string artifactDirectory)
    {
        // put_file writes freely under the artifact directory. A bundle-extract directory there -- the
        // default one, or one --artifacts moved -- would let a caller plant native code the service loads
        // on its next start.
        string[] args = artifacts is null
            ? ["--install-service", "--http", "http://0.0.0.0:4024"]
            : ["--install-service", "--http", "http://0.0.0.0:4024", "--artifacts", artifacts];
        var unit = LinuxServiceInstallOptions.Parse(args).UnitFile("/opt/linuxdiag/LinuxDiag.Mcp");

        Assert.DoesNotContain("DOTNET_BUNDLE_EXTRACT_BASE_DIR", unit, StringComparison.Ordinal);
        Assert.DoesNotContain(artifactDirectory, unit, StringComparison.Ordinal);
    }

    [Fact]
    public void No_restart_on_failure_is_honoured()
    {
        var options = LinuxServiceInstallOptions.Parse(
            ["--install-service", "--http", "http://0.0.0.0:4024", "--no-restart-on-failure"]);

        Assert.Contains("Restart=no", options.UnitFile("/opt/linuxdiag/LinuxDiag.Mcp"), StringComparison.Ordinal);
    }

    [Fact]
    public void A_service_name_that_could_escape_its_paths_is_refused()
    {
        // The name becomes part of /etc/systemd/system/<name>.service and /etc/linuxdiag/<name>.env.
        Assert.Throws<ConfigurationException>(() => LinuxServiceInstallOptions.Parse(
            ["--install-service", "--http", "http://0.0.0.0:4024", "--service-name", "../x"]));
    }

    [Fact]
    public void Reinstalling_from_the_installed_binary_does_not_copy_it_onto_itself()
    {
        // Review Focus 1: the running file cannot be opened for write ("text file busy"), and a partial
        // copy would be worse -- the next start would run a truncated binary.
        Assert.False(LinuxServiceInstaller.NeedsCopy("/opt/linuxdiag/LinuxDiag.Mcp", "/opt/linuxdiag/LinuxDiag.Mcp"));
        Assert.True(LinuxServiceInstaller.NeedsCopy("/home/op/LinuxDiag.Mcp", "/opt/linuxdiag/LinuxDiag.Mcp"));
    }

    [Fact]
    public void A_failed_start_is_detected_rather_than_trusting_enable_now()
    {
        // Measured on Ubuntu 24.04: `systemctl enable --now` exits 0 even when the start fails or the
        // unit never becomes ready, so an installer that trusted it announced "installed and started" over
        // a service that was not. A plain start does report a Type=notify failure, and is-active catches
        // a process that exits after forking.
        var commands = LinuxServiceInstaller.StartCommands("linuxdiag").Select(c => string.Join(' ', c)).ToList();

        // restart, not start: on a service that is already running, start is a no-op that exits 0, so a
        // re-install to change grants, bind or token would change nothing that is running.
        Assert.Equal(["daemon-reload", "enable linuxdiag", "restart linuxdiag", "is-active --quiet linuxdiag"], commands);
        Assert.DoesNotContain(commands, c => c.Contains("--now", StringComparison.Ordinal));
    }

    [Fact]
    public void Uninstall_says_so_when_there_was_nothing_to_remove_or_disable_failed()
    {
        var (missingCode, missing) = LinuxServiceInstaller.UninstallOutcome("linuxdiag", unitExisted: false, disableExit: 1);
        Assert.Equal(1, missingCode);
        Assert.Contains("no service named 'linuxdiag'", missing, StringComparison.Ordinal);

        var (failedCode, failed) = LinuxServiceInstaller.UninstallOutcome("linuxdiag", unitExisted: true, disableExit: 1);
        Assert.Equal(4, failedCode);
        Assert.Contains("disable", failed, StringComparison.Ordinal);

        var (okCode, ok) = LinuxServiceInstaller.UninstallOutcome("linuxdiag", unitExisted: true, disableExit: 0);
        Assert.Equal(0, okCode);
        Assert.Contains("removed 'linuxdiag'", ok, StringComparison.Ordinal);
    }

    [Fact]
    public void Update_self_is_not_reported_unavailable_just_because_systemd_run_is_missing()
    {
        // The helper falls back to setsid when the server is not a systemd service, so a missing
        // systemd-run must not make capabilities call update_self unusable.
        var requirement = new LinuxDiag.Mcp.Diagnostics.Capabilities.LinuxCapabilityRequirements().Requirements["update_self"];

        Assert.Null(requirement.RequiredExecutable);
    }

    [LinuxFact]
    public void The_unit_file_replaces_a_link_at_its_path_rather_than_writing_through_it()
    {
        // `systemctl mask` leaves the unit path as a link to /dev/null. Writing through it would change
        // the link's target -- as root -- instead of installing the unit.
        var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld-unit-{Guid.NewGuid():N}")).FullName;
        try
        {
            var target = Path.Combine(dir, "elsewhere");
            File.WriteAllText(target, "untouched");
            var unit = Path.Combine(dir, "linuxdiag.service");
            File.CreateSymbolicLink(unit, target);

            LinuxServiceInstaller.WriteFresh(unit, "[Unit]\n", LinuxServiceInstaller.UnitFileMode);

            Assert.Null(new FileInfo(unit).LinkTarget);
            Assert.Equal("[Unit]\n", File.ReadAllText(unit));
            Assert.Equal(LinuxServiceInstaller.UnitFileMode, File.GetUnixFileMode(unit));
            Assert.Equal("untouched", File.ReadAllText(target));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [LinuxFact]
    public void The_env_file_replacing_a_loose_one_ends_up_owner_only()
    {
        // Review Focus 2: the token file is the credential. A 0644 file already at the path must not leave
        // its mode behind.
        var path = Path.Combine(Path.GetTempPath(), $"ld-env-{Guid.NewGuid():N}");
        File.WriteAllText(path, "old");
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        try
        {
            LinuxServiceInstaller.WriteOwnerOnly(path, "LINUXDIAG_TOKEN=x\n");

            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
            Assert.Equal("LINUXDIAG_TOKEN=x\n", File.ReadAllText(path));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
