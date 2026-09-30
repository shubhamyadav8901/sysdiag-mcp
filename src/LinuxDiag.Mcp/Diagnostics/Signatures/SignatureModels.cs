using LinuxDiag.Mcp.Linux.Packages;

namespace LinuxDiag.Mcp.Diagnostics.Signatures;

/// <param name="ResolvedPath">Where a symlinked path leads; null when the path is the file itself.</param>
/// <param name="DivertedBy">The package whose diversion moved this file, when one did.</param>
public sealed record FileSignature(
    string Path, PackageVerdict Verdict, string Detail, string? ResolvedPath, string? Package, string? PackageVersion,
    bool Conffile, string? DivertedBy, long SizeBytes, DateTimeOffset LastWriteTime, string Sha256);

public sealed record SignatureQueryResult(IReadOnlyList<FileSignature> Files, IReadOnlyList<string> NotFound, string? Limitation);

public interface ISignatureInspector
{
    SignatureQueryResult Inspect(IReadOnlyList<string> paths);
}
