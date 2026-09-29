using System.Collections;
using static Diag.Mcp.Server.EnvironmentSettings;

namespace LinuxDiag.Mcp.Configuration;

/// <summary>Server configuration, read from <c>LINUXDIAG_*</c> environment variables.</summary>
/// <remarks>
/// The same knobs as windiag's WINDIAG_* with the same meanings and defaults, so an operator's habits
/// carry across. <see cref="ToString"/> is overridden for the reason windiag's is: a record's generated
/// one would print <see cref="Token"/> into any log line that interpolated the options.
/// </remarks>
public sealed record LinuxDiagOptions
{
    /// <summary>Where artifacts go when nothing is configured: root-owned and persistent.</summary>
    public const string DefaultArtifactDirectory = "/var/lib/linuxdiag";

    public bool ReadOnly { get; init; }

    public TimeSpan ExternalToolTimeout { get; init; } = TimeSpan.FromSeconds(120);

    public TimeSpan UpdateDrainTimeout { get; init; } = TimeSpan.FromSeconds(1800);

    public int MaxResults { get; init; } = 50_000;

    public string? HttpBind { get; init; }

    public string? Token { get; init; }

    public bool AllowSelfUpdate { get; init; }

    public bool AllowCommandExecution { get; init; }

    public bool AllowArbitraryWrite { get; init; }

    public bool AllowArbitraryRead { get; init; }

    public string ArtifactDirectory { get; init; } = DefaultArtifactDirectory;

    /// <summary>The systemd unit this process runs as, written by --install-service.</summary>
    /// <remarks>How update_self knows to restart through systemctl rather than relaunching itself.</remarks>
    public string? ServiceName { get; init; }

    public static LinuxDiagOptions FromEnvironment() => FromEnvironment(Environment.GetEnvironmentVariables());

    public static LinuxDiagOptions FromEnvironment(IDictionary environment)
    {
        ArgumentNullException.ThrowIfNull(environment);

        return new LinuxDiagOptions
        {
            ReadOnly = ReadBoolean(environment, "LINUXDIAG_READ_ONLY", defaultValue: false),
            AllowSelfUpdate = ReadBoolean(environment, "LINUXDIAG_ALLOW_SELF_UPDATE", defaultValue: false),
            AllowCommandExecution = ReadBoolean(environment, "LINUXDIAG_ALLOW_COMMAND_EXECUTION", defaultValue: false),
            AllowArbitraryWrite = ReadBoolean(environment, "LINUXDIAG_ALLOW_ARBITRARY_WRITE", defaultValue: false),
            AllowArbitraryRead = ReadBoolean(environment, "LINUXDIAG_ALLOW_ARBITRARY_READ", defaultValue: false),
            ExternalToolTimeout = TimeSpan.FromSeconds(
                ReadInt32(environment, "LINUXDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS", 120, min: 1, max: 3600)),
            UpdateDrainTimeout = TimeSpan.FromSeconds(
                ReadInt32(environment, "LINUXDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS", 1800, min: 1, max: 86_400)),
            MaxResults = ReadInt32(environment, "LINUXDIAG_MAX_RESULTS", 50_000, min: 1, max: 10_000_000),
            HttpBind = NullIfBlank(Read(environment, "LINUXDIAG_HTTP_BIND")),
            Token = NullIfBlank(Read(environment, "LINUXDIAG_TOKEN")),
            ArtifactDirectory = ReadDirectory(environment, "LINUXDIAG_ARTIFACT_DIR", DefaultArtifactDirectory),
            ServiceName = NullIfBlank(Read(environment, "LINUXDIAG_SERVICE_NAME"))
        };
    }

    /// <summary>A loggable summary, with the token redacted.</summary>
    public string Describe() =>
        $"readOnly={ReadOnly}, externalToolTimeout={ExternalToolTimeout.TotalSeconds:0}s, " +
        $"updateDrainTimeout={UpdateDrainTimeout.TotalSeconds:0}s, " +
        $"maxResults={MaxResults}, httpBind={HttpBind ?? "(stdio)"}, " +
        $"token={(Token is null ? "(generated)" : "(configured)")}, artifactDir={ArtifactDirectory}, " +
        $"service={ServiceName ?? "(none)"}, " +
        $"allowSelfUpdate={AllowSelfUpdate}, allowCommandExecution={AllowCommandExecution}, " +
        $"allowArbitraryWrite={AllowArbitraryWrite}, allowArbitraryRead={AllowArbitraryRead}";

    public override string ToString() => Describe();
}
