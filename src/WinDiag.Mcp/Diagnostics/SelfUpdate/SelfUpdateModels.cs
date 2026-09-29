namespace WinDiag.Mcp.Diagnostics.SelfUpdate;

/// <summary>Outcome of accepting a staged build for installation.</summary>
/// <param name="RestartScheduled">
/// True once the helper has been launched and this process is about to exit. The caller will lose the
/// connection; that is the success case, not a failure.
/// </param>
/// <param name="Forced">
/// True when the caller asked not to wait. Running calls will be cut off and whatever they were
/// writing is orphaned.
/// </param>
/// <param name="OtherCallsInFlight">
/// Tool calls other than this one that were running when the update was accepted. The number the
/// server is about to wait for -- or, when <paramref name="Forced"/>, about to abandon.
/// </param>
/// <param name="DrainTimeoutSeconds">
/// Upper bound on that wait. Zero when forced.
/// </param>
/// <remarks>
/// Every field describes what was true at the moment the update was accepted. The result is produced
/// before the wait even begins -- it has to be, since the reply must reach the caller before the socket
/// closes -- so nothing here reports how the drain actually went. The helper log does that.
/// </remarks>
public sealed record SelfUpdateResult(
    string StagedPath,
    string LivePath,
    long SizeBytes,
    string Sha256,
    string SignatureVerdict,
    string HelperLogPath,
    bool RestartScheduled,
    bool Forced,
    int OtherCallsInFlight,
    int DrainTimeoutSeconds);

/// <summary>Replaces the running server with a staged build.</summary>
public interface ISelfUpdater
{
    /// <param name="force">
    /// Skip waiting for running tool calls. They are cut off mid-answer, which is what this mechanism
    /// used to do unconditionally.
    /// </param>
    SelfUpdateResult Update(
        string expectedSha256, string stagedFileName, bool force, CancellationToken cancellationToken);
}

/// <summary>Raised when a staged build is refused.</summary>
/// <remarks>
/// Every rejection is deliberate and final: this mechanism replaces an executable that runs elevated,
/// so "probably fine" is never an acceptable verdict.
/// </remarks>
public sealed class SelfUpdateRejectedException : Exception, IDiagnosticException
{
    public SelfUpdateRejectedException(string message) : base(message)
    {
    }
}
