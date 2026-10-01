using System.Collections;
using static Diag.Mcp.Server.EnvironmentSettings;

namespace MacDiag.Mcp.Configuration;

/// <summary>Server configuration, read from <c>MACDIAG_*</c> settings.</summary>
/// <remarks>
/// The same knobs as linuxdiag's LINUXDIAG_* with the same meanings and defaults, so an operator's habits
/// carry across. Under launchd they arrive from the env file (see <see cref="EnvFile"/>), not the plist.
/// <see cref="ToString"/> is overridden so a log line that interpolates the options never prints the token.
/// </remarks>
public sealed record MacDiagOptions
{
    /// <summary>Where artifacts go when nothing is configured: root-owned and persistent.</summary>
    public const string DefaultArtifactDirectory = "/var/db/macdiag";

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

    /// <summary>The launchd label this process runs as, written by --install-service.</summary>
    /// <remarks>How update_self knows to restart through launchctl rather than relaunching itself.</remarks>
    public string? ServiceLabel { get; init; }

    /// <summary>Launchd labels beyond the built-in list that service_control refuses to stop.</summary>
    public IReadOnlyList<string> ProtectedLabels { get; init; } = [];

    public static MacDiagOptions FromEnvironment() => FromEnvironment(Environment.GetEnvironmentVariables());

    public static MacDiagOptions FromEnvironment(IDictionary environment)
    {
        ArgumentNullException.ThrowIfNull(environment);

        return new MacDiagOptions
        {
            ReadOnly = ReadBoolean(environment, "MACDIAG_READ_ONLY", defaultValue: false),
            AllowSelfUpdate = ReadBoolean(environment, "MACDIAG_ALLOW_SELF_UPDATE", defaultValue: false),
            AllowCommandExecution = ReadBoolean(environment, "MACDIAG_ALLOW_COMMAND_EXECUTION", defaultValue: false),
            AllowArbitraryWrite = ReadBoolean(environment, "MACDIAG_ALLOW_ARBITRARY_WRITE", defaultValue: false),
            AllowArbitraryRead = ReadBoolean(environment, "MACDIAG_ALLOW_ARBITRARY_READ", defaultValue: false),
            ExternalToolTimeout = TimeSpan.FromSeconds(
                ReadInt32(environment, "MACDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS", 120, min: 1, max: 3600)),
            UpdateDrainTimeout = TimeSpan.FromSeconds(
                ReadInt32(environment, "MACDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS", 1800, min: 1, max: 86_400)),
            MaxResults = ReadInt32(environment, "MACDIAG_MAX_RESULTS", 50_000, min: 1, max: 10_000_000),
            HttpBind = NullIfBlank(Read(environment, "MACDIAG_HTTP_BIND")),
            Token = NullIfBlank(Read(environment, "MACDIAG_TOKEN")),
            ArtifactDirectory = ReadDirectory(environment, "MACDIAG_ARTIFACT_DIR", DefaultArtifactDirectory),
            ServiceLabel = NullIfBlank(Read(environment, "MACDIAG_SERVICE_LABEL")),
            ProtectedLabels = (Read(environment, "MACDIAG_PROTECTED_LABELS") ?? string.Empty)
                .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
        };
    }

    /// <summary>A loggable summary, with the token redacted.</summary>
    public string Describe() =>
        $"readOnly={ReadOnly}, externalToolTimeout={ExternalToolTimeout.TotalSeconds:0}s, " +
        $"updateDrainTimeout={UpdateDrainTimeout.TotalSeconds:0}s, " +
        $"maxResults={MaxResults}, httpBind={HttpBind ?? "(stdio)"}, " +
        $"token={(Token is null ? "(generated)" : "(configured)")}, artifactDir={ArtifactDirectory}, " +
        $"serviceLabel={ServiceLabel ?? "(none)"}, protectedLabels={string.Join(',', ProtectedLabels)}, " +
        $"allowSelfUpdate={AllowSelfUpdate}, allowCommandExecution={AllowCommandExecution}, " +
        $"allowArbitraryWrite={AllowArbitraryWrite}, allowArbitraryRead={AllowArbitraryRead}";

    public override string ToString() => Describe();
}
