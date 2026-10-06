namespace LinuxDiag.Mcp.Hosting;

/// <summary>Refuses any argument this server does not know, before anything acts on the rest.</summary>
/// <remarks>
/// Options were looked up by exact spelling and everything else was dropped, so `--readonly` at install, or
/// `--read-only` on a server started by hand, gave a writable root server and said nothing. A grant is a
/// privilege boundary: a typo in one must fail loudly, as a typo in a LINUXDIAG_* grant variable already does.
/// </remarks>
public static class LinuxCommandLine
{
    public enum Mode
    {
        /// <summary>A server started by hand: --http, and nothing else -- its grants are LINUXDIAG_* variables.</summary>
        Server,

        Install,

        /// <summary>--uninstall-service or --service-status.</summary>
        Manage,
    }

    private static readonly string[] ServiceActions = ["--install-service", "--uninstall-service", "--service-status"];

    private static readonly string[] InstallSwitches =
    [
        "--install-service", "--token-stdin", "--allow-self-update", "--allow-command-execution", "--allow-arbitrary-write",
        "--allow-arbitrary-read", "--read-only", "--no-restart-on-failure",
    ];

    private static readonly string[] InstallValues = ["--http", "--token", "--service-name", "--artifacts"];

    /// <summary>What a by-hand run sets instead of an install option.</summary>
    private static readonly Dictionary<string, string> Variables = new(StringComparer.Ordinal)
    {
        ["--read-only"] = "LINUXDIAG_READ_ONLY=1",
        ["--allow-self-update"] = "LINUXDIAG_ALLOW_SELF_UPDATE=1",
        ["--allow-command-execution"] = "LINUXDIAG_ALLOW_COMMAND_EXECUTION=1",
        ["--allow-arbitrary-write"] = "LINUXDIAG_ALLOW_ARBITRARY_WRITE=1",
        ["--allow-arbitrary-read"] = "LINUXDIAG_ALLOW_ARBITRARY_READ=1",
        ["--artifacts"] = "LINUXDIAG_ARTIFACT_DIR=<dir>",
        ["--token"] = "LINUXDIAG_TOKEN",
        ["--token-stdin"] = "LINUXDIAG_TOKEN",
    };

    /// <summary>Checks the arguments for whichever mode they ask for.</summary>
    public static void Require(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        var actions = ServiceActions.Where(args.Contains).ToList();
        if (actions.Count > 1)
        {
            throw new ConfigurationException($"{string.Join(" and ", actions)} were both given; give only one.");
        }

        Require(args, actions.FirstOrDefault() switch
        {
            null => Mode.Server,
            "--install-service" => Mode.Install,
            _ => Mode.Manage,
        });
    }

    public static void Require(IReadOnlyList<string> args, Mode mode)
    {
        ArgumentNullException.ThrowIfNull(args);

        var (switches, values) = mode switch
        {
            Mode.Install => (InstallSwitches, InstallValues),
            Mode.Manage => (new[] { "--uninstall-service", "--service-status" }, new[] { "--service-name" }),
            _ => (Array.Empty<string>(), Array.Empty<string>()),
        };
        var known = switches.Concat(values).Concat(mode == Mode.Server ? ["--http"] : Array.Empty<string>()).ToHashSet(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];

            // As HttpBind.Resolve reads it: any case, and on a by-hand run the address is optional.
            var name = mode == Mode.Server && string.Equals(arg, "--http", StringComparison.OrdinalIgnoreCase) ? "--http" : arg;
            if (!known.Contains(name))
            {
                throw new ConfigurationException(Unknown(arg, mode));
            }

            if (!seen.Add(name))
            {
                throw new ConfigurationException($"{name} was given more than once; give it once.");
            }

            if (mode == Mode.Server)
            {
                // Same rule as HttpBind: a following argument is the address unless it looks like an option.
                if (i + 1 < args.Count && !args[i + 1].StartsWith('-'))
                {
                    i++;
                }
            }
            else if (values.Contains(name))
            {
                // The next argument is the value whatever it looks like -- a pinned token may start with a dash --
                // unless it is one of the options themselves: `--artifacts --read-only` made "--read-only" the
                // directory and dropped the grant.
                if (i + 1 >= args.Count || known.Contains(args[i + 1]))
                {
                    throw new ConfigurationException($"{name} needs a value.{Nothing(mode)}");
                }

                i++;
            }
        }
    }

    private static string Unknown(string arg, Mode mode) => mode switch
    {
        Mode.Server when Variables.TryGetValue(arg, out var variable) =>
            $"'{arg}' is an --install-service option. A server started by hand takes its settings from the " +
            $"environment: set {variable} instead. Nothing was started.",
        Mode.Server =>
            $"'{arg}' is not an option. A server started by hand takes only --http [<url>]; its grants and settings are " +
            "LINUXDIAG_* variables (see --help). Nothing was started.",
        Mode.Install =>
            $"'{arg}' is not an --install-service option. It takes --http <url>, --token <t> or --token-stdin, " +
            "--service-name <n>, --artifacts <dir>, --allow-self-update, --allow-command-execution, " +
            "--allow-arbitrary-write, --allow-arbitrary-read, --read-only and --no-restart-on-failure." + Nothing(mode),
        _ => $"'{arg}' is not an option here; --uninstall-service and --service-status take only --service-name <n>.{Nothing(mode)}",
    };

    private static string Nothing(Mode mode) => mode == Mode.Install ? " Nothing was installed." : " Nothing was done.";
}
