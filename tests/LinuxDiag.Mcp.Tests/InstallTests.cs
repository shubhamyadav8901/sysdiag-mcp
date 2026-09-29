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
