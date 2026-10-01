namespace MacDiag.Mcp.Diagnostics.Signatures;

public enum SignatureVerdict
{
    Valid,
    AdHoc,
    Unsigned,
    Invalid,
    Unknown,
}

/// <param name="ResolvedPath">Where a symlinked path leads; null when the path is the file itself.</param>
/// <param name="Authorities">The signing certificate chain, leaf first.</param>
/// <param name="Gatekeeper">spctl's assessment of the app bundle the file is in, or "not applicable".</param>
/// <param name="Package">The installer package whose receipt names the file; null for drag-installed and App Store apps.</param>
public sealed record FileSignature(
    string Path, SignatureVerdict Verdict, string Detail, string? ResolvedPath, string? Identifier, string? TeamId,
    IReadOnlyList<string> Authorities, bool HardenedRuntime, string? Gatekeeper, string? Package, string? PackageVersion,
    long SizeBytes, DateTimeOffset LastWriteTime, string Sha256);

public sealed record SignatureQueryResult(IReadOnlyList<FileSignature> Files, IReadOnlyList<string> NotFound, string? Limitation);

public interface ISignatureInspector
{
    Task<SignatureQueryResult> InspectAsync(IReadOnlyList<string> paths, CancellationToken cancellationToken);
}
