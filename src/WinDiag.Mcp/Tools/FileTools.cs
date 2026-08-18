using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics.Files;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>put_file</c>.</summary>
public sealed record PutFileResult(string Summary, FileWriteResult File);

/// <summary>Receiving a file over the server's own channel, so staging needs no SMB share.</summary>
/// <remarks>The read side lives in <see cref="FileReadTools"/>, which a read-only server still gets.</remarks>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class FileTools
{
    /// <summary>
    /// Largest file accepted in one call, decoded. Kept in step with the HTTP request-body limit set in
    /// Program.cs — this is the smaller of the two, so the tool gives the clearer error.
    /// </summary>
    /// <remarks>
    /// Generous enough for the compressed server binary (~48&#160;MB) and every Sysinternals binary, and
    /// bounded because the content arrives as base64 in a single JSON message held in memory on both
    /// ends. Genuinely large artifacts — multi-gigabyte dumps — are not moved this way; they stay on the
    /// UNC path capture_dump already returns, for exactly this reason.
    /// </remarks>
    public const int MaxFileBytes = 128 * 1024 * 1024;

    private readonly IFileReceiver _receiver;

    public FileTools(IFileReceiver receiver)
    {
        _receiver = receiver;
    }

    [McpServerTool(
        Name = "put_file",
        Title = "Write a file on the host",
        ReadOnly = false,
        Destructive = true,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Write a file onto the machine hosting this server, sent as base64, without needing an SMB " +
        "share. Use it to stage an updated server build for update_self, to place the Sysinternals " +
        "binaries, or to drop an input file - anything that previously went over \\\\host\\C$. " +
        "By default it may only write inside the directories this server owns (its own folder and the " +
        "artifact directory), which is all staging needs; writing anywhere else requires the server to " +
        "have been started with WINDIAG_ALLOW_ARBITRARY_WRITE. " +
        "Pass expectedSha256 to have the written file verified and rolled back on mismatch - the same " +
        "integrity check the share copy did. " +
        "A file too big for one message - a self-contained binary is tens of MB, which a 32-bit server " +
        "cannot decode from base64 in one go - is sent in chunks: the first call writes fresh, each " +
        "later call sets append=true, and only the last passes expectedSha256, of the whole assembled " +
        "file. Any one call is capped at ~128 MB; multi-gigabyte dumps stay on the UNC path " +
        "capture_dump returns.")]
    public PutFileResult PutFile(
        [Description(@"Destination path on the host, e.g. C:\WinDiag\WinDiag.Mcp.new.exe")]
        string path,
        [Description("The file's bytes (or this chunk's bytes), base64-encoded.")]
        string contentBase64,
        [Description("SHA-256 the finished file must have; verified after writing, rolled back on mismatch. For a chunked send, pass it only on the last chunk.")]
        string? expectedSha256 = null,
        [Description("Set false to refuse rather than replace an existing file at the path.")]
        bool overwrite = true,
        [Description("Append to the file instead of replacing it - used for the second and later chunks of a large file.")]
        bool append = false,
        [Description("SHA-256 of THIS call's bytes, checked before writing so a chunk corrupted in transit is caught at the chunk. Safe to re-send on failure.")]
        string? chunkSha256 = null,
        CancellationToken cancellationToken = default)
    {
        var content = Decode(contentBase64);

        if (content.Length > MaxFileBytes)
        {
            throw new FileTransferException(
                $"The file is {content.Length:N0} bytes, over the {MaxFileBytes:N0}-byte limit for a " +
                "single put_file. Multi-gigabyte artifacts are not moved this way; a dump stays on the " +
                "UNC path capture_dump returns.");
        }

        var result = _receiver.Receive(
            new FileWriteRequest(path, content, expectedSha256, overwrite, append, chunkSha256), cancellationToken);

        return new PutFileResult(Render(result), result);
    }

    /// <summary>Decodes the payload, turning malformed base64 into a message the caller can act on.</summary>
    private static byte[] Decode(string contentBase64)
    {
        if (string.IsNullOrEmpty(contentBase64))
        {
            throw new FileTransferException("contentBase64 is empty. Send the file's bytes base64-encoded.");
        }

        try
        {
            return Convert.FromBase64String(contentBase64);
        }
        catch (FormatException ex)
        {
            throw new FileTransferException(
                $"contentBase64 is not valid base64: {ex.Message}. Encode the raw file bytes, not a " +
                "path or a data: URI.", ex);
        }
    }

    internal static string Render(FileWriteResult result)
    {
        var builder = new StringBuilder();

        builder.Append(result.Overwrote ? "Replaced " : "Wrote ")
            .Append(result.Path)
            .Append("  (").Append(result.SizeBytes.ToString("N0", CultureInfo.InvariantCulture))
            .Append(" bytes)");

        builder.AppendLine().Append("SHA-256 ").Append(result.Sha256);

        if (result.Scope == WriteScope.Arbitrary)
        {
            // Worth stating: this write used the arbitrary-write grant, i.e. it landed outside the
            // directories windiag owns. Silent would hide that a broad permission was exercised.
            builder.AppendLine().Append("Written outside the server's own directories, using the " +
                                        "arbitrary-write grant.");
        }

        return builder.ToString();
    }
}
