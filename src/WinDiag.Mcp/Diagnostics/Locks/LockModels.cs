namespace WinDiag.Mcp.Diagnostics.Locks;

/// <summary>How Restart Manager classifies a holding process.</summary>
public enum LockHolderKind
{
    Unknown,
    MainWindow,
    OtherWindow,
    Service,
    Explorer,
    Console,

    /// <summary>A process Restart Manager considers critical, which it will not offer to restart.</summary>
    Critical
}

/// <summary>One process holding the queried path open.</summary>
/// <param name="ProcessId">PID reported by Restart Manager.</param>
/// <param name="ProcessName">Image name, or "(exited)" when the process is gone or the PID was reused.</param>
/// <param name="FriendlyName">Display name Restart Manager reported, when it has one.</param>
/// <param name="ServiceShortName">Service short name, for service holders.</param>
/// <param name="StartedAt">Process start time, used to detect PID reuse.</param>
/// <param name="StillRunning">
/// False when the process has exited since the query, or when the PID now belongs to a different
/// process. Distinguishing those from a live holder matters: acting on a recycled PID targets an
/// innocent process.
/// </param>
/// <remarks>
/// The nullable members are written even when null. The tool's output schema is generated from this
/// record and lists them as required, while the serializer omits nulls by default -- so a holder that is
/// not a service (no <see cref="ServiceShortName"/>) produced JSON the client rejected outright, failing
/// the call at exactly the moment the tool had found something. Present-and-null satisfies both.
/// <para>This record wore three <c>JsonIgnore(Never)</c> attributes for that reason. The same defect
/// was then found in every other result model -- an unsigned file has no signer, a listening socket no
/// remote address -- so the rule now lives once in <c>ServerBuilder.ToolJsonOptions</c> and applies to
/// all of them. The attributes are gone rather than left as no-ops, so nobody copies them believing
/// per-property annotation is what makes a new model safe.</para>
/// </remarks>
public sealed record LockHolder(
    int ProcessId,
    string ProcessName,
    string? FriendlyName,
    string? ServiceShortName,
    LockHolderKind Kind,
    DateTimeOffset? StartedAt,
    bool StillRunning);

/// <summary>Result of a lock query, including how much of the truth it represents.</summary>
/// <param name="Exhaustive">
/// Always false for Restart Manager. Carried explicitly so the rendering layer cannot forget that an
/// empty holder list is "none found by this method", not "nothing holds this file".
/// </param>
public sealed record LockQueryResult(
    string Path,
    IReadOnlyList<LockHolder> Holders,
    bool Exhaustive);
