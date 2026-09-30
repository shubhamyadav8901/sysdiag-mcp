using System.ComponentModel;
using System.Globalization;
using System.Text;
using LinuxDiag.Mcp.Diagnostics.Signatures;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

/// <summary>Structured result of <c>file_signatures</c>.</summary>
public sealed record FileSignaturesResult(string Summary, IReadOnlyList<FileSignature> Files, IReadOnlyList<string> NotFound, string? Limitation);

[McpServerToolType]
public sealed class SignatureTools(ISignatureInspector signatures)
{
    [McpServerTool(
        Name = "file_signatures",
        Title = "File integrity and package",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Report, for one or more files, the SHA-256, size and modification time, the installed package that owns " +
        "each (dpkg), and whether its content matches the dpkg database - the Linux answer to 'is this the file the " +
        "package shipped'. Symlinks are followed, conffiles are told apart from binaries, and diversions and " +
        "usr-merge paths are understood. Matching the database is integrity, not provenance: root can rewrite the " +
        "database, so a match is not a signature. Use it to confirm a deployed binary, to spot a file changed after " +
        "installation, or to find a program no package installed.")]
    public FileSignaturesResult FileSignatures(
        [Description("Full paths of the files to inspect")] string[] paths)
    {
        var result = signatures.Inspect(paths);
        return new FileSignaturesResult(Render(result), result.Files, result.NotFound, result.Limitation);
    }

    internal static string Render(SignatureQueryResult result)
    {
        var builder = new StringBuilder();
        if (result.Limitation is { } limitation)
        {
            builder.Append("WARNING: ").AppendLine(limitation);
        }

        foreach (var missing in result.NotFound)
        {
            builder.Append("NOT FOUND: ").AppendLine(missing);
        }

        foreach (var file in result.Files)
        {
            builder.Append(file.Path);
            if (file.ResolvedPath is { } resolved)
            {
                builder.Append(" -> ").Append(resolved);
            }

            builder.AppendLine();
            builder.Append("  ").Append(file.Verdict.ToString().ToUpperInvariant()).Append(" - ").AppendLine(file.Detail);
            if (file.Package is { } package)
            {
                builder.Append("  Package: ").Append(package);
                if (file.PackageVersion is { } version)
                {
                    builder.Append(' ').Append(version);
                }

                if (file.Conffile)
                {
                    builder.Append(" (configuration file)");
                }

                if (file.DivertedBy is { } divertedBy)
                {
                    builder.Append(" (diverted by ").Append(divertedBy).Append(')');
                }

                builder.AppendLine();
            }

            builder.Append("  ").Append(file.SizeBytes.ToString("N0", CultureInfo.InvariantCulture)).Append(" bytes, modified ")
                .AppendLine(file.LastWriteTime.ToString("u", CultureInfo.InvariantCulture));
            builder.Append("  SHA-256: ").AppendLine(file.Sha256);
        }

        return builder.ToString().TrimEnd();
    }
}
