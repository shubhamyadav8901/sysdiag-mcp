namespace MacDiag.Mcp.Hosting;

/// <summary>Refuses a command line with anything this server would not read, before anything runs.</summary>
/// <remarks>
/// <para>Each option is looked up by its exact spelling where it is used, and nothing looked at what was left over. So
/// "--install-service ... --readonly" installed a root daemon with every write tool, "MacDiag.Mcp --http ...
/// --read-only" -- by analogy with the install flags -- served one, and "--token --read-only" made "--read-only" the
/// token. A grant only ever removes risk when it is spelled right, so a wrong spelling must fail loudly, as a
/// mistyped MACDIAG_* value already does.</para>
/// <para>Checked against the whole command line rather than inside each parser, so the switches Program.cs reads for
/// itself (--env-file, --http, the service actions) are held to the same rule.</para>
/// </remarks>
public static class MacCommandLine
{
    private const string Install = "--install-service";
    private const string Uninstall = "--uninstall-service";
    private const string Status = "--service-status";

    /// <summary>The install options that are grants, and the variable that sets each on a server started by hand.</summary>
    private static readonly Dictionary<string, string> Grants = new(StringComparer.Ordinal)
    {
        ["--read-only"] = "MACDIAG_READ_ONLY=1",
        ["--allow-self-update"] = "MACDIAG_ALLOW_SELF_UPDATE=1",
        ["--allow-command-execution"] = "MACDIAG_ALLOW_COMMAND_EXECUTION=1",
        ["--allow-arbitrary-write"] = "MACDIAG_ALLOW_ARBITRARY_WRITE=1",
        ["--allow-arbitrary-read"] = "MACDIAG_ALLOW_ARBITRARY_READ=1",
    };

    /// <summary>The other install options a by-hand run has a variable for.</summary>
    private static readonly Dictionary<string, string> InstallSettings = new(StringComparer.Ordinal)
    {
        ["--token"] = "MACDIAG_TOKEN",
        ["--token-stdin"] = "MACDIAG_TOKEN",
        ["--artifacts"] = "MACDIAG_ARTIFACT_DIR",
    };

    public static void Check(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        var actions = args.Where(a => a is Install or Uninstall or Status).Distinct(StringComparer.Ordinal).ToList();
        if (actions.Count > 1)
        {
            throw new ConfigurationException(
                $"{string.Join(" and ", actions)} were both given; give only one of {Install}, {Uninstall} and {Status}. Nothing was done.");
        }

        var action = actions.SingleOrDefault();
        var (flags, valued, outcome) = action switch
        {
            Install => (new[] { Install, "--token-stdin" }.Concat(Grants.Keys).ToArray(), new[] { "--http", "--token", "--label", "--artifacts" }, "Nothing was installed."),
            Uninstall => (new[] { Uninstall, "--purge" }, new[] { "--label" }, "Nothing was removed."),
            Status => (new[] { Status }, new[] { "--label" }, "Nothing was done."),
            _ => (Array.Empty<string>(), new[] { "--env-file" }, "The server was not started."),
        };

        var given = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            if (arg is "--help" or "-h" || flags.Contains(arg, StringComparer.Ordinal))
            {
                continue;
            }

            // Read by HttpBind, in any case and with the address optional, falling back to MACDIAG_HTTP_BIND.
            if (action is null && string.Equals(arg, "--http", StringComparison.OrdinalIgnoreCase))
            {
                Once("--http");
                i += i + 1 < args.Count && !args[i + 1].StartsWith('-') ? 1 : 0;
                continue;
            }

            if (valued.Contains(arg, StringComparer.Ordinal))
            {
                Once(arg);
                // A value that is itself an option is a value forgotten: "--token --read-only" took the grant as the token.
                if (i + 1 >= args.Count || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    throw new ConfigurationException($"{arg} needs a value{(i + 1 < args.Count ? $", and '{args[i + 1]}' is an option" : string.Empty)}. {outcome}");
                }

                i++;
                continue;
            }

            throw new ConfigurationException(Unknown(arg, action, outcome));
        }

        void Once(string option)
        {
            if (!given.Add(option.ToLowerInvariant()))
            {
                throw new ConfigurationException($"{option} was given more than once; give it once. {outcome}");
            }
        }
    }

    private static string Unknown(string arg, string? action, string outcome)
    {
        var known = Grants.Keys.Concat(InstallSettings.Keys)
            .Concat([Install, Uninstall, Status, "--purge", "--label", "--http", "--env-file", "--help"]);
        var meant = known.FirstOrDefault(k => !string.Equals(k, arg, StringComparison.Ordinal) && Letters(k) == Letters(arg));
        var spelling = meant is null ? string.Empty : $" Did you mean {meant}?";
        var option = meant ?? arg;

        if (action is null && (Grants.TryGetValue(option, out var variable) || InstallSettings.TryGetValue(option, out variable)))
        {
            return $"'{arg}' is not an option of a server started by hand.{spelling} {option} is an {Install} option; " +
                   $"for a server started by hand, set {variable} in its environment or its --env-file. {outcome}";
        }

        var where = action is null ? "a server started by hand" : action;
        return $"'{arg}' is not an option of {where}.{spelling} {outcome} See --help for the options.";
    }

    /// <summary>The letters and digits alone, lower case: "--readonly", "--read_only" and "--Read-Only" all match "--read-only".</summary>
    private static string Letters(string option) => string.Concat(option.Where(char.IsLetterOrDigit)).ToLowerInvariant();
}
