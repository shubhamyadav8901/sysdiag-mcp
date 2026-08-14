namespace WinDiag.Mcp.Diagnostics.SelfUpdate;

/// <summary>Outcome of accepting a staged build for installation.</summary>
/// <param name="RestartScheduled">
/// True once the helper has been launched and this process is about to exit. The caller will lose the
/// connection; that is the success case, not a failure.
/// </param>
public sealed record SelfUpdateResult(
    string StagedPath,
    string LivePath,
    long SizeBytes,
    string Sha256,
    string SignatureVerdict,
    string HelperLogPath,
    bool RestartScheduled);

/// <summary>Replaces the running server with a staged build.</summary>
public interface ISelfUpdater
{
    SelfUpdateResult Update(string expectedSha256, string stagedFileName, CancellationToken cancellationToken);
}

/// <summary>Raised when a staged build is refused.</summary>
/// <remarks>
/// Every rejection is deliberate and final: this mechanism replaces an executable that runs elevated,
/// so "probably fine" is never an acceptable verdict.
/// </remarks>
public sealed class SelfUpdateRejectedException : Exception
{
    public SelfUpdateRejectedException(string message) : base(message)
    {
    }
}
