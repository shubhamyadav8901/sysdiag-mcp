namespace Diag.Mcp.Server.Files;

/// <summary>Where a transferred file sits, relative to the directories windiag owns.</summary>
/// <remarks>Reported for reads as well as writes; the same boundary governs both directions.</remarks>
public enum WriteScope
{
    /// <summary>Inside a directory windiag owns (its own folder or the artifact directory). Always allowed.</summary>
    WinDiag,

    /// <summary>Anywhere else. Allowed only when the matching arbitrary read/write grant is enabled.</summary>
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
/// <param name="Append">
/// Append these bytes to the file rather than replacing it. This is how a large file is sent in
/// pieces: the first chunk writes fresh, each later chunk appends. A single base64 argument big enough
/// to hold a whole self-contained binary (tens of MB) is too much for a 32-bit server's JSON pipeline
/// to decode in one go, so the caller splits it — and the integrity check moves to the last chunk,
/// which passes <see cref="ExpectedSha256"/> for the assembled whole.
/// </param>
/// <param name="ChunkSha256">
/// The hash of <em>this call's</em> bytes, checked in memory before anything is written. It catches a
/// chunk corrupted in transit at the chunk itself rather than as an opaque whole-file mismatch minutes
/// later — and because the check happens before the append, a rejected chunk leaves the file exactly
/// as it was, so re-sending that chunk is safe. Distinct from <see cref="ExpectedSha256"/>, which is
/// the finished file's hash.
/// </param>
public sealed record FileWriteRequest(
    string Path,
    byte[] Content,
    string? ExpectedSha256 = null,
    bool Overwrite = true,
    bool Append = false,
    string? ChunkSha256 = null);

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

/// <summary>A slice of a file to read back off the machine hosting the server.</summary>
/// <param name="Path">The file to read, resolved on the target.</param>
/// <param name="Offset">Byte offset to start at. A whole file is fetched by walking this forward.</param>
/// <param name="Length">
/// How many bytes to return. Capped by the server: the bytes come back base64-encoded, so a large slice
/// costs a third again on the wire and has to be encoded in one piece on a 32-bit target.
/// </param>
/// <param name="IncludeWholeFileHash">
/// Compute the hash of the ENTIRE file, not just this slice. The fetch loop asks for this on the last
/// slice so the reassembled copy can be verified end to end, and skips it on every other slice because
/// it rereads the whole file.
/// </param>
public sealed record FileReadRequest(
    string Path,
    long Offset = 0,
    int Length = 0,
    bool IncludeWholeFileHash = false);

/// <summary>One slice of a file read back from the target.</summary>
/// <param name="TotalBytes">Size of the whole file, so a caller knows how far it has to walk.</param>
/// <param name="Content">The bytes of this slice.</param>
/// <param name="ChunkSha256">
/// Hash of THIS slice, so corruption on a lossy link is caught at the slice rather than as an opaque
/// whole-file mismatch at the end. The mirror of the same check on the write side.
/// </param>
/// <param name="Sha256">
/// Hash of the whole file, present only when it was asked for. What the caller compares its reassembled
/// copy against.
/// </param>
/// <param name="EndOfFile">True when this slice reaches the end, so the caller knows to stop.</param>
public sealed record FileReadResult(
    string Path,
    long Offset,
    int Length,
    long TotalBytes,
    byte[] Content,
    string ChunkSha256,
    string? Sha256,
    bool EndOfFile,
    WriteScope Scope);

/// <summary>Reads a file back over the server's own channel, so retrieval needs no SMB share.</summary>
public interface IFileSender
{
    FileReadResult Read(FileReadRequest request, CancellationToken cancellationToken);
}
