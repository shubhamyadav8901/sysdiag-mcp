using System.Collections;
using System.Globalization;

namespace WinDiag.Mcp.Configuration;

/// <summary>Raised when the environment configures the server into an unusable state.</summary>
/// <remarks>Fails fast at startup rather than surfacing as a confusing failure on the first tool call.</remarks>
public sealed class ConfigurationException : Exception
{
    public ConfigurationException(string message) : base(message)
    {
    }
}

/// <summary>Server configuration, read from <c>WINDIAG_*</c> environment variables.</summary>
/// <remarks>
/// A record for the <c>with</c> expression, but <see cref="ToString"/> is overridden deliberately:
/// a record's generated ToString prints every property, which would put <see cref="Token"/> into any
/// log line or exception message that happened to interpolate the options object.
/// </remarks>
public sealed record WinDiagOptions
{
    /// <summary>
    /// When true, tools that change machine state are not registered at all.
    /// </summary>
    /// <remarks>
    /// Dropping them from registration rather than refusing them at call time means the model never
    /// sees a capability it cannot use, so it plans around the restriction instead of retrying into it.
    /// </remarks>
    public bool ReadOnly { get; init; }

    /// <summary>Wall-clock budget for a single external tool invocation.</summary>
    /// <remarks>
    /// Every invocation is bounded. Several Sysinternals tools never terminate on their own given the
    /// wrong flags, and an unbounded child process would hang the tool call indefinitely.
    /// <para>The default allows for a machine-wide handle search, which enumerates every object type in
    /// every process and is far slower than a file-only scan.</para>
    /// </remarks>
    public TimeSpan ExternalToolTimeout { get; init; } = TimeSpan.FromSeconds(120);

    /// <summary>Upper bound on rows returned by a single tool call.</summary>
    public int MaxResults { get; init; } = 200;

    /// <summary>Address to serve MCP over HTTP on, for example <c>http://10.0.0.5:7777</c>.</summary>
    /// <remarks>
    /// There is deliberately no default. An MCP server that runs elevated on a target machine and
    /// binds somewhere the operator did not choose is a privilege boundary opened by accident.
    /// </remarks>
    public string? HttpBind { get; init; }

    /// <summary>Bearer token required on every HTTP request. Generated at startup when unset.</summary>
    /// <remarks>
    /// Read from the environment and never from a command-line argument. This server's own
    /// <c>process_list</c> exposes command lines to every local user, so a <c>--token</c> switch would
    /// publish the credential to exactly the audience it is meant to exclude.
    /// </remarks>
    public string? Token { get; init; }

    /// <summary>Where capture artifacts (dumps, activity traces) are written.</summary>
    /// <remarks>
    /// Defaults under the temp directory rather than beside the executable: the exe is often on a share
    /// or in a read-only location on a target machine, and a dump can be several gigabytes. Callers
    /// never choose the directory — they receive the resulting path — so a caller cannot aim a
    /// multi-gigabyte write at an arbitrary location on an elevated server.
    /// </remarks>
    public string ArtifactDirectory { get; init; } = DefaultArtifactDirectory;

    /// <summary>Default artifact location, used when nothing is configured.</summary>
    public static string DefaultArtifactDirectory =>
        Path.Combine(Path.GetTempPath(), "windiag");

    /// <summary>Reads options from the process environment.</summary>
    public static WinDiagOptions FromEnvironment() => FromEnvironment(Environment.GetEnvironmentVariables());

    /// <summary>Reads options from an explicit environment dictionary, for tests.</summary>
    public static WinDiagOptions FromEnvironment(IDictionary environment)
    {
        ArgumentNullException.ThrowIfNull(environment);

        return new WinDiagOptions
        {
            ReadOnly = ReadBoolean(environment, "WINDIAG_READ_ONLY", defaultValue: false),
            ExternalToolTimeout = TimeSpan.FromSeconds(
                ReadInt32(environment, "WINDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS", 120, min: 1, max: 3600)),
            MaxResults = ReadInt32(environment, "WINDIAG_MAX_RESULTS", 200, min: 1, max: 10_000),
            HttpBind = NullIfBlank(Read(environment, "WINDIAG_HTTP_BIND")),
            Token = NullIfBlank(Read(environment, "WINDIAG_TOKEN")),
            ArtifactDirectory = ReadDirectory(environment, "WINDIAG_ARTIFACT_DIR")
        };
    }

    /// <summary>A loggable summary, with the token redacted.</summary>
    public string Describe() =>
        $"readOnly={ReadOnly}, externalToolTimeout={ExternalToolTimeout.TotalSeconds:0}s, " +
        $"maxResults={MaxResults}, httpBind={HttpBind ?? "(stdio)"}, " +
        $"token={(Token is null ? "(generated)" : "(configured)")}, artifactDir={ArtifactDirectory}";

    /// <summary>Redacted by construction — see the note on the type.</summary>
    public override string ToString() => Describe();

    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    /// <summary>Reads a directory path, rejecting a malformed one at startup rather than mid-capture.</summary>
    /// <remarks>
    /// Deliberately resolved to a full path here. A relative artifact directory would otherwise land
    /// wherever the process happened to be started from, which on a target machine is unpredictable and
    /// makes the returned path useless to the caller.
    /// </remarks>
    private static string ReadDirectory(IDictionary environment, string name)
    {
        var raw = NullIfBlank(Read(environment, name));
        if (raw is null)
        {
            return DefaultArtifactDirectory;
        }

        try
        {
            return Path.GetFullPath(raw.Trim());
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ConfigurationException($"{name}='{raw}' is not a usable directory path: {ex.Message}");
        }
    }

    private static string? Read(IDictionary environment, string name) =>
        environment.Contains(name) ? environment[name] as string : null;

    private static bool ReadBoolean(IDictionary environment, string name, bool defaultValue)
    {
        var raw = Read(environment, name);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return defaultValue;
        }

        // Deliberately strict. These flags remove capability or add risk, so a typo like
        // WINDIAG_READ_ONLY=ture must fail loudly rather than silently granting write access.
        return raw.Trim().ToLowerInvariant() switch
        {
            "1" or "true" or "yes" or "on" => true,
            "0" or "false" or "no" or "off" => false,
            _ => throw new ConfigurationException(
                $"{name}='{raw}' is not a boolean. Use one of: 1/true/yes/on or 0/false/no/off.")
        };
    }

    private static int ReadInt32(IDictionary environment, string name, int defaultValue, int min, int max)
    {
        var raw = Read(environment, name);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return defaultValue;
        }

        if (!int.TryParse(raw.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
        {
            throw new ConfigurationException($"{name}='{raw}' is not an integer.");
        }

        if (value < min || value > max)
        {
            throw new ConfigurationException($"{name}={value} is out of range; expected {min}..{max}.");
        }

        return value;
    }
}
