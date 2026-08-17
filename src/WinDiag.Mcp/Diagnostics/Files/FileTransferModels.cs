namespace WinDiag.Mcp.Diagnostics.Files;

/// <summary>Where a received file was allowed to land.</summary>
public enum WriteScope
{
    /// <summary>Inside a directory windiag owns (its own folder or the artifact directory). Always allowed.</summary>
    WinDiag,

    /// <summary>Anywhere else. Allowed only when arbitrary write is enabled.</summary>
    Arbitrary
}

/// <summary>A file to write on the machine hosting the server.</summary>
/// <param name="Path">Destination path, resolved on the target.</param>
/// <param name="Content">The bytes to write.</param>
/// <param name="ExpectedSha256">
/// The hash the caller expects the written file to have. When given, the write is verified after the
/// fact and rolled back on mismatch — the same integrity check the SMB staging path did, moved onto
/// this channel. Null skips verification.
/// </param>
/// <param name="Overwrite">When false, an existing file at the path is left untouched and the call refused.</param>
public sealed record FileWriteRequest(
    string Path,
    byte[] Content,
    string? ExpectedSha256 = null,
    bool Overwrite = true);

/// <summary>What writing a file produced.</summary>
/// <param name="Scope">
/// Which permission let the write happen. Reported so a caller can see whether it landed in a
/// windiag-owned directory or used the arbitrary-write grant.
/// </param>
public sealed record FileWriteResult(
    string Path,
    long SizeBytes,
    string Sha256,
    WriteScope Scope,
    bool Overwrote);

/// <summary>Receives a file over the server's own channel, so staging needs no SMB share.</summary>
public interface IFileReceiver
{
    FileWriteResult Receive(FileWriteRequest request, CancellationToken cancellationToken);
}

/// <summary>Raised when a file could not be written, or the write was not permitted.</summary>
public sealed class FileTransferException : Exception
{
    public FileTransferException(string message) : base(message)
    {
    }

    public FileTransferException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
