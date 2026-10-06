using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Hosting;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// What `--install-service` will actually hand to sc.exe, netsh and the registry.
/// </summary>
/// <remarks>
/// <para>None of this can be tested by running it: registering a service needs administrator rights and
/// leaves a machine changed. So the parsing and the argument construction are pure and tested here,
/// and only the execution around them is not.</para>
/// <para>That split is chosen for where the mistakes are. A mis-quoted <c>binPath</c> registers
/// perfectly and then fails to start with a message about a file that does not exist; a dropped grant
/// produces a service with fewer tools than the server it replaced, and nothing says so. Both are
/// string-construction bugs, and both are invisible until a target is already broken.</para>
/// </remarks>
public sealed class ServiceInstallationTests
{
    private static ServiceInstallOptions Parse(params string[] args) =>
        ServiceInstallOptions.Parse(["--install-service", .. args]);

    [Fact]
    public void Quotes_the_executable_path_because_every_real_install_directory_has_a_space()
    {
        // C:\Users\admin\Desktop\WinDiag is a real one. Unquoted, sc.exe reads the path up to
        // the first space as the binary and the rest as arguments, and the service fails to start.
        var options = Parse("--http", "http://10.0.0.5:4024");

        var arguments = options.CreateArguments(@"C:\Program Files\WinDiag\WinDiag.Mcp.exe");
        var binPath = arguments[arguments.ToList().IndexOf("binPath=") + 1];

        Assert.Equal(@"""C:\Program Files\WinDiag\WinDiag.Mcp.exe"" --http http://10.0.0.5:4024", binPath);

        // sc.exe wants `key= value`, so each key keeps its trailing '=' and the value is its own
        // argument. Losing that produces "the specified service already exists" style nonsense.
        Assert.Contains("start=", arguments);
        Assert.Contains("obj=", arguments);
    }

    [Theory]
    [InlineData("auto", "auto")]
    [InlineData("delayed", "delayed-auto")]
    [InlineData("demand", "demand")]
    [InlineData("manual", "demand")]
    public void Maps_the_start_type_to_what_sc_expects(string given, string expected)
    {
        var arguments = Parse("--http", "http://x:1", "--start", given).CreateArguments(@"C:\w\x.exe");

        Assert.Equal(expected, arguments[arguments.ToList().IndexOf("start=") + 1]);
    }

    [Fact]
    public void Refuses_a_start_type_it_does_not_understand()
    {
        // Silently defaulting to demand would produce a service that does not come back after a reboot,
        // which is the one thing somebody registering a service is trying to buy.
        var ex = Assert.Throws<ConfigurationException>(() => Parse("--http", "http://x:1", "--start", "boot"));

        Assert.Contains("auto, delayed, demand", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Refuses_a_named_account_with_no_password_before_registering_anything()
    {
        // Windows accepts the registration and only then fails to log the service on, so the failure
        // arrives after everything looks like it worked.
        var ex = Assert.Throws<ConfigurationException>(
            () => Parse("--http", "http://x:1", "--account", "CONTOSO\\svc-windiag"));

        Assert.Contains("--password is required", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("LocalSystem", "LocalSystem")]
    [InlineData("localsystem", "LocalSystem")]
    [InlineData("NetworkService", @"NT AUTHORITY\NetworkService")]
    [InlineData("localservice", @"NT AUTHORITY\LocalService")]
    [InlineData(@"NT AUTHORITY\LocalSystem", "LocalSystem")]
    [InlineData(@"nt authority\networkservice", @"NT AUTHORITY\NetworkService")]
    public void Accepts_a_built_in_account_without_a_password(string account, string expected)
    {
        // Normalised to the spelling sc.exe wants rather than passed through: "NetworkService" alone is
        // not an account Windows will log a service on, and the failure surfaces only after the
        // registration has apparently succeeded. LocalSystem is the exception -- sc.exe wants that one
        // bare, without the NT AUTHORITY prefix.
        var options = Parse("--http", "http://x:1", "--account", account);

        Assert.Null(options.Password);
        Assert.Equal(expected, options.Account);
    }

    [Fact]
    public void Requires_a_bind_address_rather_than_choosing_one()
    {
        // The same rule the server itself follows: an elevated process that picks its own listening
        // address is a privilege boundary opened by accident.
        var ex = Assert.Throws<ConfigurationException>(() => ServiceInstallOptions.Parse(["--install-service"]));

        Assert.Contains("--http", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Generates_a_token_when_none_is_given_and_says_it_did()
    {
        var options = Parse("--http", "http://x:1");

        Assert.False(options.TokenWasSupplied);
        Assert.Equal(64, options.Token.Length);          // 32 bytes, hex
        Assert.NotEqual(options.Token, Parse("--http", "http://x:1").Token);

        var supplied = Parse("--http", "http://x:1", "--token", "chosen-by-hand");
        Assert.True(supplied.TokenWasSupplied);
        Assert.Equal("chosen-by-hand", supplied.Token);
    }

    [Fact]
    public void Carries_only_the_grants_that_were_asked_for()
    {
        // The failure this prevents: a by-hand server running with self-update and command execution is
        // re-registered as a service without them, comes back with 22 tools instead of 24, and nothing
        // reports it except a capabilities call nobody makes.
        var bare = Parse("--http", "http://x:1").EnvironmentBlock();

        Assert.Contains(bare, v => v.StartsWith("WINDIAG_TOKEN=", StringComparison.Ordinal));
        Assert.DoesNotContain(bare, v => v.StartsWith("WINDIAG_ALLOW_", StringComparison.Ordinal));

        var granted = Parse(
            "--http", "http://x:1",
            "--allow-self-update", "--allow-command-execution",
            "--artifacts", @"C:\WinDiagArtifacts").EnvironmentBlock();

        Assert.Contains("WINDIAG_ALLOW_SELF_UPDATE=1", granted);
        Assert.Contains("WINDIAG_ALLOW_COMMAND_EXECUTION=1", granted);
        Assert.Contains(@"WINDIAG_ARTIFACT_DIR=C:\WinDiagArtifacts", granted);
        Assert.DoesNotContain("WINDIAG_READ_ONLY=1", granted);

        // Asked for separately, because the two above were once the whole list: a target that had been
        // started by hand with arbitrary write on came back from --install-service without it, and the
        // only symptom is put_file refusing a path it used to accept.
        Assert.DoesNotContain("WINDIAG_ALLOW_ARBITRARY_WRITE=1", granted);

        Assert.DoesNotContain("WINDIAG_ALLOW_ARBITRARY_READ=1", granted);

        var everything = Parse(
            "--http", "http://x:1",
            "--allow-self-update", "--allow-command-execution",
            "--allow-arbitrary-write", "--allow-arbitrary-read").EnvironmentBlock();

        Assert.Contains("WINDIAG_ALLOW_ARBITRARY_WRITE=1", everything);

        // Read is asked for separately from write because --read-only does not imply it: a read-only
        // service is not thereby allowed to read outside the artifact directory, so a re-registration
        // that drops this comes back able to read less than the server it replaced.
        Assert.Contains("WINDIAG_ALLOW_ARBITRARY_READ=1", everything);
    }

    [Fact]
    public void Restarts_on_failure_by_default_and_backs_off()
    {
        // Without recovery a crash leaves the machine silent until somebody reboots it -- which is the
        // console visit registering a service was meant to remove.
        var options = Parse("--http", "http://x:1");
        Assert.True(options.RestartOnFailure);

        var actions = options.FailureArguments();
        Assert.Contains("restart/5000/restart/30000/restart/60000", actions);

        // Escalating waits and a long reset window, so a server crashing on startup does not spin.
        Assert.Contains("86400", actions);

        Assert.False(Parse("--http", "http://x:1", "--no-restart-on-failure").RestartOnFailure);
    }

    [Fact]
    public void Scopes_the_firewall_rule_to_one_address_on_the_port_it_actually_binds()
    {
        var options = Parse("--http", "http://10.0.0.5:4899", "--firewall-from", "192.168.46.144");

        Assert.Equal(4899, options.Port);
        Assert.Contains("localport=4899", options.FirewallAddArguments());
        Assert.Contains("remoteip=192.168.46.144", options.FirewallAddArguments());

        // Named after the service so uninstall removes exactly what install added, and nothing else.
        Assert.Contains($"name={options.FirewallRuleName}", options.FirewallDeleteArguments());
        Assert.Equal("windiag-windiag", options.FirewallRuleName);
    }

    [Fact]
    public void Records_the_service_name_so_update_self_can_restart_through_the_scm()
    {
        // Without this, update_self falls back to querying WMI for its own process id -- which on a
        // real service threw rather than answering, and a failed lookup means the helper relaunches the
        // EXECUTABLE. That starts a process the SCM knows nothing about: service reads Stopped, port
        // held, service_control start then fails. The restart path should not depend on the less
        // reliable of two ways to learn the same fact.
        var block = Parse("--http", "http://x:1", "--service-name", "windiag-lab").EnvironmentBlock();

        Assert.Contains("WINDIAG_SERVICE_NAME=windiag-lab", block);
    }

    [Fact]
    public void Leaves_the_firewall_alone_unless_asked()
    {
        Assert.Null(Parse("--http", "http://x:1").FirewallFrom);
    }

    [Fact]
    public void Names_the_service_and_its_display_name_independently()
    {
        var options = Parse("--http", "http://x:1", "--service-name", "windiag-lab", "--display-name", "windiag (lab)");

        Assert.Equal("windiag-lab", options.Name);
        Assert.Equal("windiag (lab)", options.DisplayName);
        Assert.Equal("windiag-windiag-lab", options.FirewallRuleName);

        // A service name with no display name should not fall back to the generic default, or two
        // services on one machine are indistinguishable in Services.msc.
        Assert.Equal("windiag-lab", Parse("--http", "http://x:1", "--service-name", "windiag-lab").DisplayName);
    }
    [Fact]
    public void Reads_a_pinned_token_from_standard_input_so_it_never_reaches_the_targets_command_line()
    {
        // The bootstrap scripts used to pass --token <value>, which lands in the target's process
        // creation audit (event 4688), in PSEXESVC's command line, and in this server's own
        // process_list -- one log reader then holds the fleet's token. stdin is in none of those.
        var options = ServiceInstallOptions.Parse(
            ["--install-service", "--http", "http://x:1", "--token-stdin"], new StringReader("  t0k  \r\nignored\r\n"));

        Assert.Equal("t0k", options.Token);
        Assert.True(options.TokenWasSupplied);
    }

    [Fact]
    public void Refuses_an_empty_token_on_standard_input_rather_than_generating_one_nobody_sees()
    {
        // Generating one here would install a service whose token was printed into a pipe or a log, so
        // the operator would hold a token the target does not accept and not know why every call 401s.
        var ex = Assert.Throws<ConfigurationException>(() => ServiceInstallOptions.Parse(
            ["--install-service", "--http", "http://x:1", "--token-stdin"], new StringReader("\r\n")));

        Assert.Contains("--token-stdin", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Refuses_a_token_on_both_standard_input_and_the_command_line_rather_than_one_silently_winning()
    {
        var ex = Assert.Throws<ConfigurationException>(() => ServiceInstallOptions.Parse(
            ["--install-service", "--http", "http://x:1", "--token-stdin", "--token", "other"], new StringReader("t0k\n")));

        Assert.Contains("--token-stdin", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--readonly", "--read-only")]
    [InlineData("--read_only", "--read-only")]
    [InlineData("--allow-arbitary-read", null)]
    [InlineData("--tokn", null)]
    public void Refuses_an_install_option_it_does_not_know_rather_than_installing_without_it(string typo, string? suggestion)
    {
        // Ignored, `--readonly` installed and started a fully writable LocalSystem service -- put_file,
        // service_control, process_kill -- with nothing on screen to say the restriction was dropped.
        var ex = Assert.Throws<ConfigurationException>(() => Parse("--http", "http://x:1", typo));

        Assert.Contains($"'{typo}'", ex.Message, StringComparison.Ordinal);
        if (suggestion is not null)
        {
            Assert.Contains($"'{suggestion}'", ex.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Refuses_an_option_whose_value_is_missing_rather_than_generating_a_token_in_its_place()
    {
        // A trailing `--token` used to be read as "no token given": the install generated one, and the
        // relay's targets file -- holding the token the operator meant -- then 401'd on every call.
        var ex = Assert.Throws<ConfigurationException>(() => Parse("--http", "http://x:1", "--token"));

        Assert.Contains("--token", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--token", "--allow-command-execution")]
    [InlineData("--token", "--read-only")]
    [InlineData("--artifacts", "--read-only")]
    [InlineData("--password", "--allow-self-update")]
    [InlineData("--token", "")]
    [InlineData("--account", " ")]
    public void Refuses_an_option_whose_value_was_dropped_rather_than_taking_the_next_option_as_it(string option, string next)
    {
        // Windows PowerShell 5.1 drops an empty string argument to a native exe, so `--token $tok` with
        // an empty $tok arrives as `--token --allow-command-execution`: read that way, the install had
        // command execution granted AND a bearer token anyone could guess. An empty value is refused too,
        // because PowerShell 7 does pass it, and a token of "" is no token at all.
        var ex = Assert.Throws<ConfigurationException>(
            () => Parse("--http", "http://x:1", option, next, "--service-name", "w"));

        Assert.Contains($"{option} needs a value", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Still_accepts_a_value_that_merely_begins_with_a_single_dash()
    {
        // Only "--" marks an option: every option windiag has is spelled that way, while a password or a
        // pinned token is free to begin with one dash.
        var options = Parse("--http", "http://x:1", "--token", "-abc123", "--account", @".\diag", "--password", "-p4ss");

        Assert.Equal("-abc123", options.Token);
        Assert.Equal("-p4ss", options.Password);
    }

    [Fact]
    public void Refuses_an_option_given_twice_rather_than_silently_using_the_first()
    {
        var ex = Assert.Throws<ConfigurationException>(
            () => Parse("--http", "http://x:1", "--artifacts", @"C:", "--artifacts", @"C:"));

        Assert.Contains("--artifacts", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Accepts_every_option_the_help_text_documents()
    {
        // The other half of refusing unknown options: a documented one refused would be a regression
        // nobody could work around.
        var options = ServiceInstallOptions.Parse(
            [
                "--install-service", "--http", "http://x:1", "--service-name", "n", "--display-name", "d",
                "--start", "demand", "--account", "LocalService", "--token", "t", "--artifacts", @"C:",
                "--firewall-from", "10.0.0.1", "--allow-self-update", "--allow-command-execution",
                "--allow-arbitrary-write", "--allow-arbitrary-read", "--read-only", "--no-restart-on-failure"
            ],
            stdin: null);

        Assert.True(options.ReadOnly);
        Assert.False(options.RestartOnFailure);
    }

    [Fact]
    public void Treats_a_directory_holding_only_windiag_files_as_its_own_and_anything_else_as_somebody_elses()
    {
        // The installer restricts the server's directory to SYSTEM and Administrators. Run from the
        // Downloads folder -- the README does say "run it from any shell" -- that would take the user's
        // own Downloads away from them, so a directory holding anything else is refused instead.
        Assert.Empty(ServiceInstallOptions.ForeignToServerDirectory(
        [
            "WinDiag.Mcp.exe", "WinDiag.Mcp.new.exe", "handle64.exe", "Procmon64.exe", "autorunsc64.exe",
            "handle.exe", "windiag-staged.json", "install-token.tmp", "install-windiag.cmd",

            // The documented Procmon filter override, read from beside the server.
            "windiag.pmc"
        ]));

        Assert.Equal(
            ["holiday.jpg", "setup.msi"],
            ServiceInstallOptions.ForeignToServerDirectory(["WinDiag.Mcp.exe", "holiday.jpg", "setup.msi"]));
    }

    [Fact]
    public void Every_install_option_the_parser_accepts_is_documented_in_the_help_text()
    {
        // Now that an unknown option is refused, an accepted one missing from --help is an option nobody
        // can discover -- and the operator's only recourse is reading this file.
        foreach (var option in ServiceInstallOptions.InstallOptions)
        {
            Assert.Contains(option, ServerBuilder.HelpText, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("--uninstall-service")]
    [InlineData("--service-status")]
    public void Service_management_takes_only_a_service_name(string command)
    {
        Assert.Equal("lab", ServiceInstallOptions.ManagedServiceName([command, "--service-name", "lab"]));
        Assert.Equal("windiag", ServiceInstallOptions.ManagedServiceName([command]));

        // A typo here would otherwise act on the default service rather than the one meant -- and for
        // uninstall that is deleting the wrong service.
        var ex = Assert.Throws<ConfigurationException>(
            () => ServiceInstallOptions.ManagedServiceName([command, "--servicename", "lab"]));
        Assert.Contains("'--servicename'", ex.Message, StringComparison.Ordinal);
        Assert.Contains("'--service-name'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Refuses_two_service_commands_at_once()
    {
        Assert.Throws<ConfigurationException>(
            () => ServiceInstallOptions.ManagedServiceName(["--service-status", "--uninstall-service"]));
        Assert.Throws<ConfigurationException>(
            () => Parse("--http", "http://x:1", "--uninstall-service"));
    }
}
