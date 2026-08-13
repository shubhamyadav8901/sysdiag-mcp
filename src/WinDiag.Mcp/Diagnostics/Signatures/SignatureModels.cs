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
    string Sha256);

/// <summary>Result of inspecting one or more files.</summary>
public sealed record SignatureQueryResult(IReadOnlyList<FileSignature> Files, IReadOnlyList<string> NotFound);

/// <summary>Verifies file signatures and reads version metadata.</summary>
public interface ISignatureInspector
{
    SignatureQueryResult Inspect(IReadOnlyList<string> paths, CancellationToken cancellationToken);
}
