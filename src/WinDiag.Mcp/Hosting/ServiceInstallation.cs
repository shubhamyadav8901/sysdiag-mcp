using System.Globalization;
using System.Security.Cryptography;
using WinDiag.Mcp.Configuration;

namespace WinDiag.Mcp.Hosting;

/// <summary>How the Service Control Manager should start the server.</summary>
public enum ServiceStart
{
    /// <summary>At boot.</summary>
    Auto,

    /// <summary>At boot, but after the services Windows starts first -- gentler on boot time.</summary>
    DelayedAuto,

    /// <summary>Only when something starts it.</summary>
    Demand
}

/// <summary>
/// Everything <c>--install-service</c> was asked to configure.
/// </summary>
/// <remarks>
/// A record with a pure parser, kept apart from the code that runs sc.exe, because the parsing and the
/// argument construction are where the mistakes actually are -- a mis-quoted <c>binPath</c> produces a
/// service that registers cleanly and fails to start, which is the least debuggable outcome available.
/// Those parts are unit-tested; the execution around them is not.
/// </remarks>
public sealed record ServiceInstallOptions
{
    /// <summary>Short service name, as sc.exe and <c>service_control</c> know it.</summary>
    public string Name { get; init; } = "windiag";

    /// <summary>What Services.msc shows.</summary>
    public string DisplayName { get; init; } = "windiag";

    /// <summary>The address to serve on. Required: there is deliberately no default bind.</summary>
    public required string Bind { get; init; }

    public ServiceStart Start { get; init; } = ServiceStart.Auto;

    /// <summary>
    /// The account the service runs as, in sc.exe's spelling.
    /// </summary>
    /// <remarks>
    /// LocalSystem by default because the diagnostics need it, but worth choosing deliberately: as
    /// LocalSystem the server presents on the network as the machine account, which on a domain may
    /// carry permissions nobody intended to hand a diagnostics server.
    /// </remarks>
    public string Account { get; init; } = "LocalSystem";

    public string? Password { get; init; }

    /// <summary>Bearer token. Generated when not supplied, never left to chance.</summary>
    public required string Token { get; init; }

    public string? ArtifactDirectory { get; init; }

    public bool AllowSelfUpdate { get; init; }

    public bool AllowCommandExecution { get; init; }

    /// <summary>Lets put_file write outside the artifact directory.</summary>
    /// <remarks>
    /// The widest of the four, and the reason it is its own flag: the other grants are bounded by what
    /// they do -- self-update replaces one known file, command execution is at least visible in what it
    /// was asked to run -- while this one lets anyone holding the token place a file anywhere the
    /// service account can reach. Granted deliberately or not at all.
    /// </remarks>
    public bool AllowArbitraryWrite { get; init; }

    /// <summary>Lets the read tools open files outside the artifact directory.</summary>
    /// <remarks>
    /// Registered for the same reason as the rest: a by-hand server that had it, re-registered as a
    /// service without it, comes back able to read less than it could an hour ago. Sharper here than
    /// elsewhere because <see cref="ReadOnly"/> does not imply it -- a read-only service is not
    /// automatically allowed to read anywhere -- so the two look interchangeable and are not.
    /// </remarks>
    public bool AllowArbitraryRead { get; init; }

    public bool ReadOnly { get; init; }

    /// <summary>Remote address allowed through the firewall, or null to leave the firewall alone.</summary>
    public string? FirewallFrom { get; init; }

    /// <summary>
    /// Whether the SCM restarts the service if the process dies.
    /// </summary>
    /// <remarks>
    /// On by default, and the reason is the whole point of registering a service: without recovery a
    /// crash leaves the machine silent until someone reboots it, which is the console visit this was
    /// meant to remove.
    /// </remarks>
    public bool RestartOnFailure { get; init; } = true;

    /// <summary>True when the caller supplied the token rather than having one generated.</summary>
    public bool TokenWasSupplied { get; init; }

    /// <summary>The port the bind address listens on, for the firewall rule.</summary>
    public int Port =>
        Uri.TryCreate(Bind, UriKind.Absolute, out var uri) && uri.Port > 0 ? uri.Port : 4024;

    /// <summary>The three service commands. Exactly one may be given.</summary>
    public static readonly IReadOnlyList<string> Commands = ["--install-service", "--uninstall-service", "--service-status"];

    // Every option --install-service understands. Anything else is refused rather than ignored: an
    // ignored `--readonly` installed a fully writable LocalSystem service, and an ignored trailing
    // `--token` installed one with a generated token nobody had put in the relay's targets file.
    private static readonly string[] InstallValueOptions =
        ["--http", "--service-name", "--display-name", "--start", "--account", "--password", "--token", "--artifacts", "--firewall-from"];

    private static readonly string[] InstallFlags =
    [
        "--install-service", "--token-stdin", "--allow-self-update", "--allow-command-execution",
        "--allow-arbitrary-write", "--allow-arbitrary-read", "--read-only", "--no-restart-on-failure"
    ];

    /// <summary>Every option --install-service accepts, for the test that keeps --help in step with it.</summary>
    internal static IEnumerable<string> InstallOptions => [.. InstallValueOptions, .. InstallFlags];

    /// <summary>Parses the install switches, or explains what is wrong with them.</summary>
    public static ServiceInstallOptions Parse(IReadOnlyList<string> args) => Parse(args, stdin: null);

    /// <summary>Refuses any argument the given service command does not understand.</summary>
    /// <remarks>
    /// Run before elevation as well as by <see cref="Parse(IReadOnlyList{string}, TextReader?)"/>, so a
    /// typo is reported in the operator's own terminal instead of behind a UAC prompt in a window that
    /// closes the moment it exits.
    /// </remarks>
    public static void CheckArguments(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        var command = args.FirstOrDefault(a => Commands.Contains(a, StringComparer.Ordinal))
            ?? throw new ConfigurationException("No service command was given.");

        var (values, flags) = command == "--install-service"
            ? (InstallValueOptions, InstallFlags)
            : (new[] { "--service-name" }, new[] { command });

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Count; i++)
        {
            var argument = args[i];
            var known = values.FirstOrDefault(v => string.Equals(v, argument, StringComparison.OrdinalIgnoreCase))
                ?? flags.FirstOrDefault(f => string.Equals(f, argument, StringComparison.OrdinalIgnoreCase));

            if (known is null)
            {
                throw new ConfigurationException(
                    $"'{argument}' is not a {command} option{Suggest(argument, [.. values, .. flags])}. Nothing "
                    + "was changed. Run --help for the options.");
            }

            // Repeated, the parser below would silently take the first -- which, for a token or an
            // artifact directory, is a coin toss over which one the operator actually meant.
            if (!seen.Add(known))
            {
                throw new ConfigurationException($"{known} was given more than once; give it once. Nothing was changed.");
            }

            if (values.Contains(known, StringComparer.Ordinal))
            {
                if (i + 1 >= args.Count)
                {
                    throw new ConfigurationException($"{known} needs a value. Nothing was changed.");
                }

                i++;
            }
        }
    }

    /// <summary>The service an <c>--uninstall-service</c> or <c>--service-status</c> run is about.</summary>
    /// <remarks>
    /// Validated like an install: a misspelt <c>--service-name</c> would otherwise fall back to the
    /// default name, and for uninstall that removes a service nobody asked to remove.
    /// </remarks>
    public static string ManagedServiceName(IReadOnlyList<string> args)
    {
        CheckArguments(args);

        for (var i = 0; i < args.Count - 1; i++)
        {
            if (string.Equals(args[i], "--service-name", StringComparison.OrdinalIgnoreCase))
            {
                return args[i + 1];
            }
        }

        return "windiag";
    }

    /// <summary>" -- did you mean '--read-only'?" for a spelling that differs only in dashes, underscores or case.</summary>
    internal static string Suggest(string argument, IEnumerable<string> known)
    {
        static string Squash(string s) => new string(s.Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();

        var match = known.FirstOrDefault(k => Squash(k) == Squash(argument));
        return match is null ? string.Empty : $" -- did you mean '{match}'?";
    }

    /// <summary>Parses the install switches, or explains what is wrong with them.</summary>
    /// <param name="args">The command line.</param>
    /// <param name="stdin">Where --token-stdin reads the token from; the process's standard input when null.</param>
    public static ServiceInstallOptions Parse(IReadOnlyList<string> args, TextReader? stdin)
    {
        ArgumentNullException.ThrowIfNull(args);
        CheckArguments(args);

        string? Value(string name)
        {
            for (var i = 0; i < args.Count - 1; i++)
            {
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                {
                    return args[i + 1];
                }
            }

            return null;
        }

        bool Flag(string name) => args.Any(a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));

        var bind = Value("--http")
            ?? Environment.GetEnvironmentVariable("WINDIAG_HTTP_BIND")
            ?? throw new ConfigurationException(
                "--install-service needs the address the service will serve on, for example "
                + "'--http http://10.0.0.5:4024'. There is deliberately no default: a server that runs "
                + "elevated and picks its own bind address is a privilege boundary opened by accident.");

        if (!Uri.TryCreate(bind, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ConfigurationException(
                $"'{bind}' is not a usable bind address. Give a full URL including scheme and port.");
        }

        var start = (Value("--start") ?? "auto").ToLowerInvariant() switch
        {
            "auto" => ServiceStart.Auto,
            "delayed" or "delayed-auto" => ServiceStart.DelayedAuto,
            "demand" or "manual" => ServiceStart.Demand,
            var other => throw new ConfigurationException(
                $"--start '{other}' is not one of: auto, delayed, demand.")
        };

        var account = Value("--account") ?? "LocalSystem";
        var password = Value("--password");

        // A named account without a password produces a service that registers and then fails to start
        // with a logon failure -- refused up front instead, where the message can say why.
        //
        // Compared case-insensitively, and that is not a nicety: a case-SENSITIVE check here read
        // "localsystem" as a domain account and demanded a password for the built-in one everybody
        // uses, which is a confusing refusal for a correct command.
        var builtIn = account.ToLowerInvariant() is "localsystem"
            or "localservice" or "networkservice"
            or "nt authority\\localsystem"
            or "nt authority\\localservice"
            or "nt authority\\networkservice";

        if (!builtIn && string.IsNullOrEmpty(password))
        {
            throw new ConfigurationException(
                $"--account '{account}' is not a built-in account, so --password is required. Windows "
                + "will not start a service that cannot log on, and it reports that only after the "
                + "registration appears to have succeeded.");
        }

        // --token-stdin keeps a pinned token off the target's command line, where process-creation
        // auditing (event 4688), PSEXESVC and this server's own process_list would all show it. Both at
        // once is refused: whichever silently won, the operator installed a token they did not mean.
        if (Flag("--token-stdin") && Flag("--token"))
        {
            throw new ConfigurationException("--token-stdin and --token both supply the token; give only one.");
        }

        var supplied = Flag("--token-stdin") ? ReadToken(stdin ?? Console.In) : Value("--token");

        return new ServiceInstallOptions
        {
            Name = Value("--service-name") ?? "windiag",
            DisplayName = Value("--display-name") ?? Value("--service-name") ?? "windiag",
            Bind = bind,
            Start = start,
            Account = builtIn ? Normalise(account) : account,
            Password = password,
            Token = supplied ?? GenerateToken(),
            TokenWasSupplied = supplied is not null,
            ArtifactDirectory = Value("--artifacts"),
            AllowSelfUpdate = Flag("--allow-self-update"),
            AllowCommandExecution = Flag("--allow-command-execution"),
            AllowArbitraryWrite = Flag("--allow-arbitrary-write"),
            AllowArbitraryRead = Flag("--allow-arbitrary-read"),
            ReadOnly = Flag("--read-only"),
            FirewallFrom = Value("--firewall-from"),
            RestartOnFailure = !Flag("--no-restart-on-failure")
        };
    }

    private static string ReadToken(TextReader reader)
    {
        var token = reader.ReadLine()?.Trim();
        return string.IsNullOrEmpty(token)
            ? throw new ConfigurationException(
                "--token-stdin was given but standard input held no token. Nothing was installed.")
            : token;
    }

    // What a directory windiag was deployed into holds: the server and its staged successor, the
    // Sysinternals tools found beside it, deploy-target's manifest, and bootstrap-target's two files
    // that exist only while the installer runs.
    private static readonly string[] ServerDirectoryFiles =
    [
        "WinDiag.Mcp*", "handle*.exe", "Procmon*.exe", "autorunsc*.exe", "windiag-staged.json",
        "install-token.tmp", "install-windiag.cmd"
    ];

    /// <summary>The names in a server directory that are not windiag's, in the order given.</summary>
    /// <remarks>
    /// The installer restricts an exposed server directory to SYSTEM and Administrators -- which, for a
    /// server run from a Downloads or Desktop folder, would take that folder away from its own user.
    /// A directory holding anything else is therefore refused rather than restricted.
    /// </remarks>
    public static IReadOnlyList<string> ForeignToServerDirectory(IEnumerable<string> names) =>
        names.Where(name => !ServerDirectoryFiles.Any(
            pattern => System.IO.Enumeration.FileSystemName.MatchesSimpleExpression(pattern, name, ignoreCase: true))).ToList();

    /// <summary>256 bits of randomness, so nobody is tempted to pick one by hand.</summary>
    public static string GenerateToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

    /// <summary>Built-in accounts in the exact spelling sc.exe accepts.</summary>
    /// <remarks>
    /// LocalSystem is bare; the other two need the NT AUTHORITY prefix. Passing "NetworkService" alone
    /// registers a service Windows then refuses to log on, and it reports that only after the
    /// registration looks like it worked. Every spelling accepted as built-in above must map here, or
    /// one of them passes through unchanged and fails at start time.
    /// </remarks>
    private static string Normalise(string account) => account.ToLowerInvariant() switch
    {
        "localsystem" or @"nt authority\localsystem" => "LocalSystem",
        "localservice" or "nt authority\\localservice" => "NT AUTHORITY\\LocalService",
        "networkservice" or "nt authority\\networkservice" => "NT AUTHORITY\\NetworkService",
        _ => account
    };

    /// <summary>
    /// The argument list for <c>sc.exe create</c>.
    /// </summary>
    /// <remarks>
    /// sc.exe wants <c>key= value</c> with the space as the separator, so each key carries its trailing
    /// <c>=</c> and the value follows as its own argument. The binPath value quotes the executable
    /// itself, because every real install directory here has a space in it and an unquoted path makes
    /// sc.exe treat the rest as arguments to something that does not exist.
    /// </remarks>
    public IReadOnlyList<string> CreateArguments(string executablePath)
    {
        var startValue = Start switch
        {
            ServiceStart.Auto => "auto",
            ServiceStart.DelayedAuto => "delayed-auto",
            _ => "demand"
        };

        var arguments = new List<string>
        {
            "create", Name,
            "binPath=", $"\"{executablePath}\" --http {Bind}",
            "start=", startValue,
            "obj=", Account,
            "DisplayName=", DisplayName
        };

        if (!string.IsNullOrEmpty(Password))
        {
            arguments.Add("password=");
            arguments.Add(Password);
        }

        return arguments;
    }

    /// <summary>
    /// The argument list for <c>sc.exe failure</c>: bring it back if the process dies.
    /// </summary>
    /// <remarks>
    /// Three escalating waits rather than an immediate loop, and a reset window of a day, so a server
    /// that is crashing on startup does not spin restarting forever while looking healthy in between.
    /// </remarks>
    public IReadOnlyList<string> FailureArguments() =>
        ["failure", Name, "reset=", "86400", "actions=", "restart/5000/restart/30000/restart/60000"];

    /// <summary>
    /// The per-service environment, as the REG_MULTI_SZ the SCM hands the process.
    /// </summary>
    /// <remarks>
    /// The installer restricts this key to SYSTEM and Administrators before writing it
    /// (<see cref="ProtectedAcl.ProtectServiceKey"/>): sc.exe creates it with the Services key's ACL,
    /// under which every local user can read its values. A machine-wide variable would be readable by
    /// every local user too, and with self-update or command execution enabled the token is equivalent
    /// to code execution -- so where it is written, and who can read that, matters more than that it is set.
    /// </remarks>
    public IReadOnlyList<string> EnvironmentBlock()
    {
        // The service's own name, so update_self can restart it through the SCM rather than by
        // launching the executable -- which would start a process the SCM knows nothing about. The
        // server can also discover this by querying WMI for its own process id, but that is the
        // fallback for a hand-registered service: on a real one the query threw instead of answering,
        // and a restart path should not depend on the less reliable of two ways to learn the same fact.
        var values = new List<string>
        {
            $"WINDIAG_TOKEN={Token}",
            $"WINDIAG_SERVICE_NAME={Name}"
        };

        if (!string.IsNullOrWhiteSpace(ArtifactDirectory))
        {
            values.Add($"WINDIAG_ARTIFACT_DIR={ArtifactDirectory}");
        }

        // Written only when granted. An explicit "=0" would be equivalent, but absent is what a
        // by-hand deployment looks like, and the two should not read differently.
        if (AllowSelfUpdate)
        {
            values.Add("WINDIAG_ALLOW_SELF_UPDATE=1");
        }

        if (AllowCommandExecution)
        {
            values.Add("WINDIAG_ALLOW_COMMAND_EXECUTION=1");
        }

        if (AllowArbitraryWrite)
        {
            values.Add("WINDIAG_ALLOW_ARBITRARY_WRITE=1");
        }

        if (AllowArbitraryRead)
        {
            values.Add("WINDIAG_ALLOW_ARBITRARY_READ=1");
        }

        if (ReadOnly)
        {
            values.Add("WINDIAG_READ_ONLY=1");
        }

        return values;
    }

    /// <summary>Inbound rule for the bind port, scoped to one remote address.</summary>
    /// <remarks>Scoped to an address rather than a subnet, which is what the deployment notes ask for.</remarks>
    public IReadOnlyList<string> FirewallAddArguments() =>
    [
        "advfirewall", "firewall", "add", "rule",
        $"name={FirewallRuleName}",
        "dir=in", "action=allow", "protocol=TCP",
        $"localport={Port.ToString(CultureInfo.InvariantCulture)}",
        $"remoteip={FirewallFrom}"
    ];

    public IReadOnlyList<string> FirewallDeleteArguments() =>
        ["advfirewall", "firewall", "delete", "rule", $"name={FirewallRuleName}"];

    /// <summary>Named after the service so uninstall removes exactly what install added.</summary>
    public string FirewallRuleName => $"windiag-{Name}";
}
