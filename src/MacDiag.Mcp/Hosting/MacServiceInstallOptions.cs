using System.Security;
using System.Text;

namespace MacDiag.Mcp.Hosting;

/// <summary>Everything --install-service was asked to configure. A pure parser; the side effects are elsewhere.</summary>
/// <remarks>
/// Kept apart from the code that writes files and runs launchctl, as linuxdiag's install options are, because
/// the parsing and the generated plist and env file are where the mistakes are -- and those are testable on
/// any machine, while the installation itself is not.
/// </remarks>
public sealed record MacServiceInstallOptions
{
    public const string DefaultLabel = "com.windiag.macdiag";

    /// <summary>How long launchd gives the daemon to stop before SIGKILL; written into the plist.</summary>
    /// <remarks>Explicit rather than launchd's default, so the installer's wait for an unload can be derived from it.</remarks>
    public static readonly TimeSpan ExitTimeOut = TimeSpan.FromSeconds(20);

    public string LabelName { get; init; } = DefaultLabel;

    /// <summary>One settings file per label, so a second install never rewrites, and its uninstall never deletes, the first's.</summary>
    public string EnvironmentFilePath => EnvironmentFilePathFor(LabelName);

    public static string EnvironmentFilePathFor(string label) => $"{MacServiceInstaller.SettingsDirectory}/{label}.env";

    public required string Bind { get; init; }

    public required string Token { get; init; }

    public bool TokenWasSupplied { get; init; }

    public string? ArtifactDirectory { get; init; }

    public bool AllowSelfUpdate { get; init; }

    public bool AllowCommandExecution { get; init; }

    public bool AllowArbitraryWrite { get; init; }

    public bool AllowArbitraryRead { get; init; }

    public bool ReadOnly { get; init; }

    public string PlistPath => PlistPathFor(LabelName);

    public static string PlistPathFor(string label) => $"/Library/LaunchDaemons/{label}.plist";

    public static MacServiceInstallOptions Parse(IReadOnlyList<string> args) => Parse(args, stdin: null);

    /// <param name="stdin">Where --token-stdin reads the token from; the process's standard input when null.</param>
    public static MacServiceInstallOptions Parse(IReadOnlyList<string> args, TextReader? stdin)
    {
        ArgumentNullException.ThrowIfNull(args);

        string? Value(string name)
        {
            for (var i = 0; i < args.Count - 1; i++)
            {
                if (string.Equals(args[i], name, StringComparison.Ordinal))
                {
                    return args[i + 1];
                }
            }

            return null;
        }

        bool Flag(string name) => args.Any(a => string.Equals(a, name, StringComparison.Ordinal));

        var bind = Value("--http") ?? throw new ConfigurationException(
            "--install-service needs the address the daemon will serve on, for example " +
            "'--http http://0.0.0.0:4025'. There is deliberately no default: a root server that picks its " +
            "own bind address is a privilege boundary opened by accident.");

        // Validated by the same rules the running server applies, so a daemon is never installed with an
        // address it would then refuse at startup.
        HttpBind.Resolve(["--http", bind], null, "MACDIAG_HTTP_BIND");

        var label = Label(args);
        // --token-stdin keeps a pinned token out of the command line, where sudo logs it and ps shows it.
        if (Flag("--token-stdin") && Flag("--token"))
        {
            throw new ConfigurationException("--token-stdin and --token both supply the token; give only one.");
        }

        var supplied = Flag("--token-stdin") ? ReadToken(stdin ?? Console.In) : Value("--token");
        return new MacServiceInstallOptions
        {
            LabelName = label,
            Bind = bind,
            Token = supplied ?? BearerTokenGate.GenerateToken(),
            TokenWasSupplied = supplied is not null,
            ArtifactDirectory = Value("--artifacts"),
            AllowSelfUpdate = Flag("--allow-self-update"),
            AllowCommandExecution = Flag("--allow-command-execution"),
            AllowArbitraryWrite = Flag("--allow-arbitrary-write"),
            AllowArbitraryRead = Flag("--allow-arbitrary-read"),
            ReadOnly = Flag("--read-only")
        };
    }

    private static string ReadToken(TextReader reader)
    {
        var token = reader.ReadLine()?.Trim();
        return string.IsNullOrEmpty(token)
            ? throw new ConfigurationException("--token-stdin was given but standard input held no token.")
            : token;
    }

    /// <summary>The --label value, or the default, refused if it could escape the paths it names.</summary>
    /// <remarks>
    /// One check for install, uninstall and status: the label is spliced into a plist path that is written --
    /// and, on uninstall, deleted -- as root, so it may carry no separator and cannot start with a dot.
    /// </remarks>
    public static string Label(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        var label = DefaultLabel;
        for (var i = 0; i < args.Count - 1; i++)
        {
            if (string.Equals(args[i], "--label", StringComparison.Ordinal))
            {
                label = args[i + 1];
            }
        }

        if (label.Length == 0 || label.StartsWith('.') || label.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')))
        {
            throw new ConfigurationException($"--label '{label}' may contain only letters, digits, '-', '_' and '.'.");
        }

        return label;
    }

    /// <summary>The settings file the daemon reads with --env-file: root-owned, 0600, the credential lives here.</summary>
    /// <remarks>Grants are written only when given, so an install looks exactly like a by-hand start with the same flags.</remarks>
    public string EnvironmentFile()
    {
        var env = new StringBuilder()
            .Append("MACDIAG_TOKEN=").Append(Token).Append('\n')
            .Append("MACDIAG_HTTP_BIND=").Append(Bind).Append('\n')
            .Append("MACDIAG_SERVICE_LABEL=").Append(LabelName).Append('\n');

        if (!string.IsNullOrWhiteSpace(ArtifactDirectory))
        {
            env.Append("MACDIAG_ARTIFACT_DIR=").Append(ArtifactDirectory).Append('\n');
        }

        if (AllowSelfUpdate)
        {
            env.Append("MACDIAG_ALLOW_SELF_UPDATE=1\n");
        }

        if (AllowCommandExecution)
        {
            env.Append("MACDIAG_ALLOW_COMMAND_EXECUTION=1\n");
        }

        if (AllowArbitraryWrite)
        {
            env.Append("MACDIAG_ALLOW_ARBITRARY_WRITE=1\n");
        }

        if (AllowArbitraryRead)
        {
            env.Append("MACDIAG_ALLOW_ARBITRARY_READ=1\n");
        }

        if (ReadOnly)
        {
            env.Append("MACDIAG_READ_ONLY=1\n");
        }

        return env.ToString();
    }

    /// <summary>The launchd job. World-readable by launchd's rules, so it names the env file and never holds the token.</summary>
    /// <remarks>
    /// <para>KeepAlive restarts only a failed exit: update_self and a deliberate stop exit 0 and must stay down.
    /// AbandonProcessGroup lets update_self's helper outlive the server it restarts; launchd would otherwise
    /// kill the whole group when the job stops. ProcessType Standard keeps the daemon off the throttled
    /// background tier. stderr goes to crash.log for what the runtime writes before logging exists; the
    /// server rolls its own log.</para>
    /// <para>No DOTNET_BUNDLE_EXTRACT_BASE_DIR, for linuxdiag's reason: nothing is extracted from this build.</para>
    /// </remarks>
    public string Plist(string executable) => $"""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
        	<key>Label</key>
        	<string>{Xml(LabelName)}</string>
        	<key>ProgramArguments</key>
        	<array>
        		<string>{Xml(executable)}</string>
        		<string>--env-file</string>
        		<string>{Xml(EnvironmentFilePath)}</string>
        	</array>
        	<key>RunAtLoad</key>
        	<true/>
        	<key>KeepAlive</key>
        	<dict>
        		<key>SuccessfulExit</key>
        		<false/>
        	</dict>
        	<key>AbandonProcessGroup</key>
        	<true/>
        	<key>ProcessType</key>
        	<string>Standard</string>
        	<key>ExitTimeOut</key>
        	<integer>{(int)ExitTimeOut.TotalSeconds}</integer>
        	<key>StandardErrorPath</key>
        	<string>{MacServiceInstaller.LogDirectory}/crash.log</string>
        </dict>
        </plist>

        """.ReplaceLineEndings("\n");

    private static string Xml(string value) => SecurityElement.Escape(value);
}
