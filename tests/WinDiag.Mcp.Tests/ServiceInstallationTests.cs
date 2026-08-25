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
}
