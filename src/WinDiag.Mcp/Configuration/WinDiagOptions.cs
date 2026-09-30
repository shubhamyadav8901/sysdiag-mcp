using System.Collections;
using static Diag.Mcp.Server.EnvironmentSettings;

namespace WinDiag.Mcp.Configuration;

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

    /// <summary>How long <c>update_self</c> waits for running tool calls before restarting anyway.</summary>
    /// <remarks>
    /// A backstop, not a schedule: on an idle target the drain finishes in milliseconds, and this only
    /// bounds how long a tool that never returns can hold up an update.
    /// <para>30 minutes because the call most likely to be running during an update is also the longest:
    /// <c>capture_activity</c> allows 300s of capture, 90s of overhead and up to a 15-minute export --
    /// about 21 minutes in the worst case, and truncating it is the exact failure this exists to
    /// prevent. A <c>run_command</c> may legitimately run for an hour and is NOT covered by this
    /// default; raise it, or pass force and accept the truncation.</para>
    /// <para>The upper limit is deliberately a day rather than the hour used for a single external tool,
    /// so covering a full-length run_command stays possible for anyone who wants it.</para>
    /// </remarks>
    public TimeSpan UpdateDrainTimeout { get; init; } = TimeSpan.FromSeconds(1800);

    /// <summary>Upper bound on rows returned by a single tool call.</summary>
    /// <remarks>
    /// 50000 so high-cardinality tools -- process_handles and path_handle_search above all, where a
    /// single process can hold thousands of handles -- are not truncated in the common case.
    /// <para>This bounds the ROWS a tool returns, not the prose: summaries are capped separately by
    /// <see cref="RenderLimits"/>, because a summary that grew with this would build one contiguous
    /// multi-megabyte string.</para>
    /// <para>Rows are still materialised in full before the cap is applied, so raising this far above the
    /// default trades memory on the TARGET for completeness. The win-x86 build has roughly 2 GB of
    /// address space; treat values in the millions as a per-machine experiment, not a supported mode.</para>
    /// </remarks>
    public int MaxResults { get; init; } = 50_000;

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

    /// <summary>Whether the server may replace its own executable on request.</summary>
    /// <remarks>
    /// Off unless explicitly enabled, because it changes what the bearer token protects. Without it the
    /// token guards diagnostics and capture; with it, the token guards the ability to replace an
    /// elevated binary and run it. That is a different thing to hold, and it should be a deliberate
    /// choice per deployment rather than a default.
    /// </remarks>
    public bool AllowSelfUpdate { get; init; }

    /// <summary>Whether the server may run an arbitrary command line on request.</summary>
    /// <remarks>
    /// <para>Off unless explicitly enabled, and the most consequential flag here. Every other tool
    /// answers a specific question or performs a bounded action; this one turns the bearer token into
    /// arbitrary code execution as whatever account the server runs under — SYSTEM or an administrator
    /// on a target machine. It is the one capability the diagnostics design otherwise excludes on
    /// purpose.</para>
    /// <para>It is gated the same way <see cref="AllowSelfUpdate"/> is, and <see cref="ReadOnly"/>
    /// overrides it: a read-only server must never be a shell. Enabling it is a deliberate per-deployment
    /// grant — "this token may run anything here" — not a default.</para>
    /// </remarks>
    public bool AllowCommandExecution { get; init; }

    /// <summary>Whether <c>put_file</c> may write outside the server's own directories.</summary>
    /// <remarks>
    /// <para><c>put_file</c> itself is always available on a writable server, but confined to the two
    /// directories windiag already owns — its own folder and the artifact directory. That covers the
    /// job it exists for (staging a server update for <see cref="AllowSelfUpdate"/>, staging the
    /// Sysinternals binaries, receiving capture inputs) and grants nothing SMB-to-those-folders plus the
    /// existing tools did not already allow, so it needs no flag.</para>
    /// <para>This flag widens it to write <em>anywhere</em> as the server's account. That is a genuine
    /// escalation — an arbitrary file written as SYSTEM is a step from code execution — so it is off by
    /// default and, like the other grants, overridden by <see cref="ReadOnly"/>.</para>
    /// </remarks>
    public bool AllowArbitraryWrite { get; init; }

    /// <summary>Whether <c>get_file</c> may read outside the directories windiag owns.</summary>
    /// <remarks>
    /// <para><c>get_file</c> itself is always available, confined to the same two directories as
    /// <see cref="AllowArbitraryWrite"/> covers — which is where every artifact worth retrieving already
    /// lands, because <c>capture_dump</c> and <c>capture_activity</c> write to the artifact directory.
    /// That is the job it exists for: getting a dump or a trace back without an SMB share.</para>
    /// <para>This flag widens it to read <em>anywhere</em> as the server's account. On an elevated server
    /// that is exfiltration of anything the account can open, so it is off by default. Unlike the write
    /// grant it is NOT overridden by <see cref="ReadOnly"/> — reading is what a read-only server is for,
    /// and the confinement, not the mode, is what bounds it.</para>
    /// </remarks>
    public bool AllowArbitraryRead { get; init; }

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
            AllowSelfUpdate = ReadBoolean(environment, "WINDIAG_ALLOW_SELF_UPDATE", defaultValue: false),
            AllowCommandExecution = ReadBoolean(environment, "WINDIAG_ALLOW_COMMAND_EXECUTION", defaultValue: false),
            AllowArbitraryWrite = ReadBoolean(environment, "WINDIAG_ALLOW_ARBITRARY_WRITE", defaultValue: false),
            AllowArbitraryRead = ReadBoolean(environment, "WINDIAG_ALLOW_ARBITRARY_READ", defaultValue: false),
            ExternalToolTimeout = TimeSpan.FromSeconds(
                ReadInt32(environment, "WINDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS", 120, min: 1, max: 3600)),
            UpdateDrainTimeout = TimeSpan.FromSeconds(
                ReadInt32(environment, "WINDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS", 1800, min: 1, max: 86_400)),
            MaxResults = ReadInt32(environment, "WINDIAG_MAX_RESULTS", 50_000, min: 1, max: 10_000_000),
            HttpBind = NullIfBlank(Read(environment, "WINDIAG_HTTP_BIND")),
            Token = NullIfBlank(Read(environment, "WINDIAG_TOKEN")),
            ArtifactDirectory = ReadDirectory(environment, "WINDIAG_ARTIFACT_DIR", DefaultArtifactDirectory)
        };
    }

    /// <summary>A loggable summary, with the token redacted.</summary>
    public string Describe() =>
        $"readOnly={ReadOnly}, externalToolTimeout={ExternalToolTimeout.TotalSeconds:0}s, " +
        $"updateDrainTimeout={UpdateDrainTimeout.TotalSeconds:0}s, " +
        $"maxResults={MaxResults}, httpBind={HttpBind ?? "(stdio)"}, " +
        $"token={(Token is null ? "(generated)" : "(configured)")}, artifactDir={ArtifactDirectory}, " +
        $"allowSelfUpdate={AllowSelfUpdate}, allowCommandExecution={AllowCommandExecution}, " +
        $"allowArbitraryWrite={AllowArbitraryWrite}, allowArbitraryRead={AllowArbitraryRead}";

    /// <summary>Redacted by construction — see the note on the type.</summary>
    public override string ToString() => Describe();
}
