namespace WinDiag.Mcp.Diagnostics.Signatures;

/// <summary>Authenticode verdict for a file.</summary>
public enum SignatureVerdict
{
    /// <summary>Signed and trusted.</summary>
    Valid,

    /// <summary>No signature at all, embedded or catalog.</summary>
    Unsigned,

    /// <summary>Signed, but the signature did not verify: tampered, expired, or an untrusted root.</summary>
    Untrusted,

    /// <summary>Verification could not be performed. The detail says why.</summary>
    Unknown
}

/// <summary>Identity and provenance of one file on disk.</summary>
/// <param name="CatalogSigned">
/// True when trust comes from a system catalog rather than an embedded signature. Most Windows
/// binaries are catalog-signed and have no certificate inside the file, so an embedded-signature-only
/// check would wrongly call them unsigned.
/// </param>
/// <param name="SignerSubject">
/// The full subject of the certificate WinVerifyTrust itself verified the signature with -- the catalog's
/// signer for a catalog-signed file. Unlike <see cref="Signer"/>, which names the leaf picked out of the
/// certificates embedded in the file, this cannot be steered by extra certificates added to that
/// unsigned bag, which is why it is what the update ratchet compares publishers by. Null when no
/// signature was verified far enough to name one.
/// </param>
public sealed record FileSignature(
    string Path,
    SignatureVerdict Verdict,
    string Detail,
    bool CatalogSigned,
    string? Signer,
    string? Issuer,
    DateTimeOffset? CertificateNotAfter,
    string? FileVersion,
    string? ProductVersion,
    string? CompanyName,
    string? OriginalFilename,
    long SizeBytes,
    DateTimeOffset LastWriteTime,
    string Sha256,
    string? SignerSubject = null);

/// <summary>Result of inspecting one or more files.</summary>
public sealed record SignatureQueryResult(IReadOnlyList<FileSignature> Files, IReadOnlyList<string> NotFound);

/// <summary>Verifies file signatures and reads version metadata.</summary>
public interface ISignatureInspector
{
    SignatureQueryResult Inspect(IReadOnlyList<string> paths, CancellationToken cancellationToken);

    /// <summary>
    /// Inspects one file while holding it open against writers, so its verdict, signer and hash all
    /// describe the same bytes.
    /// </summary>
    /// <exception cref="IOException">The file is open for writing elsewhere, or could not be opened.</exception>
    FileSignature InspectHeld(string path, CancellationToken cancellationToken);

    /// <summary>
    /// Inspects a file through a handle the caller already holds and has already settled the identity of,
    /// so the verdict is about that file and not whatever its path names by the time of a second open.
    /// </summary>
    /// <param name="path">A path to the held file, for the parts of the check that only take one.</param>
    /// <param name="held">
    /// Open for reading, shared for reading only, so nothing can write, rename or delete it meanwhile.
    /// </param>
    FileSignature InspectHeld(string path, FileStream held, CancellationToken cancellationToken);
}
