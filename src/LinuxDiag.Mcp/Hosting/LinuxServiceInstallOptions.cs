using System.Text;

namespace LinuxDiag.Mcp.Hosting;

/// <summary>Everything --install-service was asked to configure. A pure parser; the side effects are elsewhere.</summary>
/// <remarks>
/// Kept apart from the code that writes files and runs systemctl, as windiag's install options are,
/// because the parsing and the generated unit and env file are where the mistakes are -- and those are
/// testable on any machine, while the installation itself is not.
/// </remarks>
public sealed record LinuxServiceInstallOptions
{
    public string Name { get; init; } = "linuxdiag";

    public required string Bind { get; init; }

    public required string Token { get; init; }

    public bool TokenWasSupplied { get; init; }

    public string? ArtifactDirectory { get; init; }

    public bool AllowSelfUpdate { get; init; }

    public bool AllowCommandExecution { get; init; }

    public bool AllowArbitraryWrite { get; init; }

    public bool AllowArbitraryRead { get; init; }

    public bool ReadOnly { get; init; }

    public bool RestartOnFailure { get; init; } = true;

    public string EnvironmentFilePath => $"/etc/linuxdiag/{Name}.env";

    public string UnitFilePath => $"/etc/systemd/system/{Name}.service";

    public static LinuxServiceInstallOptions Parse(IReadOnlyList<string> args) => Parse(args, stdin: null);

    /// <param name="stdin">Where --token-stdin reads the token from; the process's standard input when null.</param>
    public static LinuxServiceInstallOptions Parse(IReadOnlyList<string> args, TextReader? stdin)
    {
        ArgumentNullException.ThrowIfNull(args);
        LinuxCommandLine.Require(args, LinuxCommandLine.Mode.Install);

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
            "--install-service needs the address the service will serve on, for example " +
            "'--http http://0.0.0.0:4024'. There is deliberately no default: a root server that picks its " +
            "own bind address is a privilege boundary opened by accident.");

        // Validated by the same rules the running server applies, so a service is never installed with
        // an address it would then refuse at startup.
        HttpBind.Resolve(["--http", bind], null, "LINUXDIAG_HTTP_BIND");

        var name = ServiceName(args);
        // --token-stdin keeps a pinned token out of the command line, where sudo logs it and ps shows it.
        // Both at once is refused: whichever silently won, the operator installed a token they did not mean.
        if (Flag("--token-stdin") && Flag("--token"))
        {
            throw new ConfigurationException("--token-stdin and --token both supply the token; give only one.");
        }

        var supplied = Flag("--token-stdin") ? ReadToken(stdin ?? Console.In) : Value("--token");

        // The installer judges the directory the kernel reaches, taking ".." from wherever a link led; the server reads
        // LINUXDIAG_ARTIFACT_DIR through GetFullPath, which folds ".." as text and resolves a relative path against
        // the service's "/". With /opt/L -> /var/lib, /opt/L/../evil was judged as /var/evil and used as /opt/evil.
        // Refused rather than normalised for one of them: either choice approves a directory the operator did not name.
        var artifacts = Value("--artifacts");
        if (artifacts is not null && (!Path.IsPathRooted(artifacts) || artifacts.Split('/').Any(c => c is "." or "..")))
        {
            throw new ConfigurationException(
                $"--artifacts {artifacts} must be an absolute path with no '.' or '..' in it: the installer and the " +
                "service would otherwise each take it to a different directory. Nothing was installed.");
        }

        return new LinuxServiceInstallOptions
        {
            Name = name,
            Bind = bind,
            Token = supplied ?? BearerTokenGate.GenerateToken(),
            TokenWasSupplied = supplied is not null,
            ArtifactDirectory = artifacts,
            AllowSelfUpdate = Flag("--allow-self-update"),
            AllowCommandExecution = Flag("--allow-command-execution"),
            AllowArbitraryWrite = Flag("--allow-arbitrary-write"),
            AllowArbitraryRead = Flag("--allow-arbitrary-read"),
            ReadOnly = Flag("--read-only"),
            RestartOnFailure = !Flag("--no-restart-on-failure")
        };
    }

    private static string ReadToken(TextReader reader)
    {
        var token = reader.ReadLine()?.Trim();
        return string.IsNullOrEmpty(token)
            ? throw new ConfigurationException("--token-stdin was given but standard input held no token.")
            : token;
    }

    /// <summary>The --service-name value, or the default, refused if it could escape the paths it names.</summary>
    /// <remarks>
    /// One check for install, uninstall and status: the name is spliced into paths that are written --
    /// and, on uninstall, deleted -- as root, so it may carry no separator and cannot start with a dot.
    /// </remarks>
    public static string ServiceName(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        var name = "linuxdiag";
        for (var i = 0; i < args.Count - 1; i++)
        {
            if (string.Equals(args[i], "--service-name", StringComparison.Ordinal))
            {
                name = args[i + 1];
            }
        }

        if (name.Length == 0 || name.StartsWith('.') || name.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')))
        {
            throw new ConfigurationException($"--service-name '{name}' may contain only letters, digits, '-', '_' and '.'.");
        }

        return name;
    }

    /// <summary>The environment file systemd hands the service: root-owned, 0600, the credential lives here.</summary>
    /// <remarks>Grants are written only when given, so an install looks exactly like a by-hand start with the same flags.</remarks>
    public string EnvironmentFile()
    {
        var env = new StringBuilder()
            .Append("LINUXDIAG_TOKEN=").Append(Token).Append('\n')
            .Append("LINUXDIAG_HTTP_BIND=").Append(Bind).Append('\n')
            .Append("LINUXDIAG_SERVICE_NAME=").Append(Name).Append('\n');

        if (!string.IsNullOrWhiteSpace(ArtifactDirectory))
        {
            env.Append("LINUXDIAG_ARTIFACT_DIR=").Append(ArtifactDirectory).Append('\n');
        }

        if (AllowSelfUpdate)
        {
            env.Append("LINUXDIAG_ALLOW_SELF_UPDATE=1\n");
        }

        if (AllowCommandExecution)
        {
            env.Append("LINUXDIAG_ALLOW_COMMAND_EXECUTION=1\n");
        }

        if (AllowArbitraryWrite)
        {
            env.Append("LINUXDIAG_ALLOW_ARBITRARY_WRITE=1\n");
        }

        if (AllowArbitraryRead)
        {
            env.Append("LINUXDIAG_ALLOW_ARBITRARY_READ=1\n");
        }

        if (ReadOnly)
        {
            env.Append("LINUXDIAG_READ_ONLY=1\n");
        }

        return env.ToString();
    }

    /// <summary>The grants written to the env file, every one named, so a flag that did not take is seen at install.</summary>
    public string Grants()
    {
        static string YesNo(bool value) => value ? "yes" : "no";
        return $"read-only: {YesNo(ReadOnly)}; allow-self-update: {YesNo(AllowSelfUpdate)}; " +
               $"allow-command-execution: {YesNo(AllowCommandExecution)}; allow-arbitrary-write: {YesNo(AllowArbitraryWrite)}; " +
               $"allow-arbitrary-read: {YesNo(AllowArbitraryRead)}";
    }

    /// <summary>The unit. Deliberately not sandboxed: a diagnostics server must see every process's /proc.</summary>
    /// <remarks>
    /// <para>No DOTNET_BUNDLE_EXTRACT_BASE_DIR. It once pointed at /var/lib/linuxdiag/.net so a service
    /// with no HOME could never fail to extract, but that is inside the artifact directory, where put_file
    /// writes freely: a caller could plant a native library for the service to load on its next start.
    /// Nothing needs the setting. This build sets neither IncludeNativeLibrariesForSelfExtract nor
    /// IncludeAllContentForSelfExtract, and the native runtime is linked into the single-file host, so
    /// nothing is extracted and HOME is never consulted -- the published binary starts with HOME unset and
    /// leaves an extract directory empty.</para>
    /// <para>Turning either property on must bring the variable back in the same change, pointed at a
    /// root-only directory put_file cannot reach (systemd's CacheDirectory= with CacheDirectoryMode=0700),
    /// never under the artifact directory.</para>
    /// </remarks>
    public string UnitFile(string executable) => $"""
        [Unit]
        Description=linuxdiag diagnostics MCP server
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=notify
        EnvironmentFile={EnvironmentFilePath}
        ExecStart={executable}
        Restart={(RestartOnFailure ? "on-failure" : "no")}
        RestartSec=5

        [Install]
        WantedBy=multi-user.target

        """.ReplaceLineEndings("\n");
}
