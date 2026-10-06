using LinuxDiag.Mcp.Hosting;

namespace LinuxDiag.Mcp.Tests;

/// <summary>Every argument is one the server knows, or nothing runs: a dropped grant must never pass unnoticed.</summary>
public sealed class CommandLineTests
{
    private const string Bind = "http://0.0.0.0:4024";

    [Theory]
    [InlineData("--readonly")]
    [InlineData("--read_only")]
    [InlineData("--allow-arbitary-read")]
    [InlineData("read-only")]
    public void A_misspelled_install_flag_is_refused_rather_than_installing_a_server_without_it(string typo)
    {
        // Review: `--install-service --http ... --readonly` installed and started a fully writable root server --
        // service_control, kill_process and put_file all registered -- with no word about the dropped flag.
        var ex = Assert.Throws<ConfigurationException>(() =>
            LinuxServiceInstallOptions.Parse(["--install-service", "--http", Bind, typo]));

        Assert.Contains($"'{typo}'", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Nothing was installed", ex.Message, StringComparison.Ordinal);
        Assert.Contains("--read-only", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_documented_install_option_is_accepted()
    {
        var options = LinuxServiceInstallOptions.Parse(
            ["--install-service", "--http", Bind, "--token", "-starts-with-a-dash", "--service-name", "lab", "--artifacts", "/srv/a",
             "--allow-self-update", "--allow-command-execution", "--allow-arbitrary-write", "--allow-arbitrary-read",
             "--read-only", "--no-restart-on-failure"]);

        Assert.Equal("-starts-with-a-dash", options.Token);
        Assert.True(options.ReadOnly);
        Assert.False(options.RestartOnFailure);
    }

    [Theory]
    [InlineData("--artifacts", "--read-only")]
    [InlineData("--service-name", "--allow-self-update")]
    public void An_option_whose_value_is_missing_does_not_swallow_the_next_flag(string option, string next)
    {
        // `--artifacts --read-only` made "--read-only" the directory, and the server writable.
        var ex = Assert.Throws<ConfigurationException>(() =>
            LinuxServiceInstallOptions.Parse(["--install-service", "--http", Bind, option, next]));

        Assert.Contains($"{option} needs a value", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--token", "--readonly")]
    [InlineData("--service-name", "--readonly")]
    [InlineData("--artifacts", "--allow-arbitary-read")]
    [InlineData("--token", "")]
    [InlineData("--token", "   ")]
    [InlineData("--service-name", "")]
    public void A_value_that_is_empty_or_looks_like_an_option_is_refused_even_when_the_option_is_misspelled(string option, string value)
    {
        // Re-check: only the server's own option names were refused as values, so `--token $TOK --readonly`
        // with $TOK empty and unquoted installed a writable root server whose bearer token was "--readonly" --
        // and, the token counting as supplied, never printed one.
        var ex = Assert.Throws<ConfigurationException>(() =>
            LinuxServiceInstallOptions.Parse(["--install-service", "--http", Bind, option, value]));

        Assert.Contains($"{option} needs a value", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Nothing was installed", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Uninstall_refuses_a_service_name_that_looks_like_an_option()
    {
        var ex = Assert.Throws<ConfigurationException>(() =>
            LinuxCommandLine.Require(["--uninstall-service", "--service-name", "--purge"]));

        Assert.Contains("--service-name needs a value", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_option_given_twice_is_refused_rather_than_one_silently_winning()
    {
        var ex = Assert.Throws<ConfigurationException>(() =>
            LinuxServiceInstallOptions.Parse(["--install-service", "--http", Bind, "--artifacts", "/a", "--artifacts", "/b"]));

        Assert.Contains("--artifacts was given more than once", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--read-only", "LINUXDIAG_READ_ONLY=1")]
    [InlineData("--allow-command-execution", "LINUXDIAG_ALLOW_COMMAND_EXECUTION=1")]
    [InlineData("--artifacts", "LINUXDIAG_ARTIFACT_DIR")]
    public void An_install_flag_on_a_server_started_by_hand_is_refused_and_points_at_its_variable(string flag, string variable)
    {
        // By analogy with the install flags, `LinuxDiag.Mcp --http ... --read-only` started a writable server.
        var ex = Assert.Throws<ConfigurationException>(() => LinuxCommandLine.Require(["--http", Bind, flag]));

        Assert.Contains(variable, ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData]
    [InlineData("--http")]
    [InlineData("--http", Bind)]
    [InlineData("--HTTP", Bind)]
    public void A_by_hand_run_takes_http_with_or_without_an_address(params string[] args) => LinuxCommandLine.Require(args);

    [Theory]
    [InlineData("--htpp", Bind)]
    [InlineData("--http", Bind, "extra")]
    [InlineData("--http", Bind, "--http", Bind)]
    public void Anything_else_on_a_by_hand_run_is_refused(params string[] args)
    {
        Assert.Throws<ConfigurationException>(() => LinuxCommandLine.Require(args));
    }

    [Theory]
    [InlineData("--uninstall-service", "--service-name", "lab")]
    [InlineData("--service-status")]
    public void Uninstall_and_status_take_only_a_service_name(params string[] args)
    {
        LinuxCommandLine.Require(args);
        Assert.Throws<ConfigurationException>(() => LinuxCommandLine.Require([.. args, "--purge"]));
    }

    [Fact]
    public void Two_service_actions_at_once_are_refused()
    {
        var ex = Assert.Throws<ConfigurationException>(() =>
            LinuxCommandLine.Require(["--install-service", "--uninstall-service", "--http", Bind]));

        Assert.Contains("only one", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_installer_says_which_grants_it_wrote()
    {
        var options = LinuxServiceInstallOptions.Parse(["--install-service", "--http", Bind, "--allow-command-execution"]);

        Assert.Equal(
            "read-only: no; allow-self-update: no; allow-command-execution: yes; allow-arbitrary-write: no; allow-arbitrary-read: no",
            options.Grants());
    }
}
