namespace Diag.Mcp.Server.SelfUpdate;

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

/// <summary>What was found about a staged build, before anything is decided about it.</summary>
/// <param name="Path">The staged file itself, for a guard that must read it.</param>
/// <param name="Sha256">Uppercase hex of the staged file.</param>
/// <param name="SignatureVerdict">The platform's verdict on its signature, as reported to the caller.</param>
/// <param name="SignatureDetail">Why, when the verdict is not a clean pass; null otherwise.</param>
/// <param name="SignerIdentity">
/// Who signed it, in a form a guard can compare with the running build's signer. Null where the platform
/// has no such notion or the signer could not be read; read in the same inspection as the hash, so the
/// two describe the same bytes.
/// </param>
public sealed record StagedBuild(
    string Path, string Sha256, long SizeBytes, string SignatureVerdict, string? SignatureDetail,
    string? SignerIdentity = null);

/// <summary>Hashes a staged build and reads its signature, the platform's way.</summary>
public interface IStagedBuildInspector
{
    StagedBuild Inspect(string path, CancellationToken cancellationToken);
}

/// <summary>A per-platform rule the staged build must satisfy beyond its hash.</summary>
/// <remarks>Throws <see cref="SelfUpdateRejectedException"/> to refuse; returning means acceptable.</remarks>
public interface IUpdateGuard
{
    void RequireAcceptable(string livePath, StagedBuild staged, CancellationToken cancellationToken);
}

/// <summary>Starts whatever swaps the staged build in once this process has exited, and brings it back.</summary>
/// <remarks>
/// Must re-verify the hash itself before moving anything: the window between the engine's check and the
/// swap is one an attacker with file access could otherwise use.
/// </remarks>
public interface IRestartHelper
{
    void Launch(string livePath, string stagedPath, string sha256, string logPath);
}

/// <summary>Where the update engine keeps its helper log, and how long it waits for running calls.</summary>
public sealed record SelfUpdateOptions(string ArtifactDirectory, TimeSpan DrainTimeout);
