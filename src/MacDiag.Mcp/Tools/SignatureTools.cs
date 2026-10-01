using System.ComponentModel;
using System.Globalization;
using System.Text;
using MacDiag.Mcp.Diagnostics.Signatures;
using ModelContextProtocol.Server;

namespace MacDiag.Mcp.Tools;

/// <summary>Structured result of <c>file_signatures</c>.</summary>
public sealed record FileSignaturesResult(string Summary, IReadOnlyList<FileSignature> Files, IReadOnlyList<string> NotFound, string? Limitation);

[McpServerToolType]
public sealed class SignatureTools(ISignatureInspector signatures)
{
    [McpServerTool(
        Name = "file_signatures",
        Title = "File signature and package",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Report, for one or more files, the SHA-256, size and modification time, the code signature (whether it " +
        "verifies, who signed it - Apple, a Developer ID team, ad hoc or nobody - and whether it uses the hardened " +
        "runtime), Gatekeeper's assessment for a file inside an app bundle, and the installer package whose receipt " +
        "names it. Symlinks are followed. A valid signature says who signed the file and that it has not changed " +
        "since; it is not a verdict on whether the signer is trustworthy. Use it to confirm a deployed binary, to " +
        "spot a file modified after signing, or to find a program nobody signed. At most 200 paths per call.")]
    public async Task<FileSignaturesResult> FileSignatures(
        [Description("Full paths of the files to inspect")] string[] paths,
        CancellationToken cancellationToken = default)
    {
        var result = await signatures.InspectAsync(paths, cancellationToken).ConfigureAwait(false);
        return new FileSignaturesResult(Render(result), result.Files, result.NotFound, result.Limitation);
    }

    internal static string Render(SignatureQueryResult result)
    {
        var builder = new StringBuilder();
        if (result.Limitation is { } limitation)
        {
            builder.Append("NOTE: ").AppendLine(RenderLimits.Printable(limitation));
        }

        foreach (var missing in result.NotFound)
        {
            builder.Append("NOT FOUND: ").AppendLine(RenderLimits.Printable(missing));
        }

        foreach (var file in result.Files.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append(RenderLimits.Printable(file.Path));
            if (file.ResolvedPath is { } resolved)
            {
                builder.Append(" -> ").Append(RenderLimits.Printable(resolved));
            }

            builder.AppendLine();
            builder.Append("  ").Append(file.Verdict.ToString().ToUpperInvariant()).Append(" - ").AppendLine(RenderLimits.Printable(file.Detail));
            if (file.Identifier is { } identifier)
            {
                builder.Append("  Identifier: ").Append(RenderLimits.Printable(identifier));
                if (file.HardenedRuntime)
                {
                    builder.Append(" (hardened runtime)");
                }

                builder.AppendLine();
            }

            if (file.Gatekeeper is { } gatekeeper && gatekeeper != "not applicable")
            {
                builder.Append("  Gatekeeper: ").AppendLine(RenderLimits.Printable(gatekeeper));
            }

            if (file.Package is { } package)
            {
                builder.Append("  Package: ").Append(RenderLimits.Printable(package));
                if (file.PackageVersion is { } version)
                {
                    builder.Append(' ').Append(RenderLimits.Printable(version));
                }

                builder.AppendLine();
            }

            builder.Append("  ").Append(file.SizeBytes.ToString("N0", CultureInfo.InvariantCulture)).Append(" bytes, modified ")
                .AppendLine(file.LastWriteTime.ToString("u", CultureInfo.InvariantCulture));
            builder.Append("  SHA-256: ").AppendLine(RenderLimits.Printable(file.Sha256));
        }

        RenderLimits.NoteElision(builder, result.Files.Count, "files");
        return builder.ToString().TrimEnd();
    }
}
