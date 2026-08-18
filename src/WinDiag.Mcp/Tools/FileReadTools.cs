using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics.Files;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>get_file</c>.</summary>
/// <remarks>
/// The bytes ride in <see cref="FileReadResult.Content"/> as base64. A caller fetching a whole file
/// walks <c>offset</c> forward until <c>endOfFile</c>, appending each slice.
/// </remarks>
public sealed record GetFileResult(string Summary, FileReadResult File);

/// <summary>
/// Reading a file back off the host, so retrieval needs no SMB share.
/// </summary>
/// <remarks>
/// Deliberately a separate tool type from <see cref="FileTools"/>, which carries the write side and is
/// registered only on a writable server. Retrieving a dump is a read, and a read-only server is exactly
/// where someone collecting artifacts is likely to be pointed -- so this one is always registered, and
/// what bounds it is the directory confinement, not the mode. Mirrors the
/// ActivityCaptureTools/ActivityQueryTools split for the same reason.
/// </remarks>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class FileReadTools
{
    private readonly IFileSender _sender;

    public FileReadTools(IFileSender sender)
    {
        _sender = sender;
    }

    [McpServerTool(
        Name = "get_file",
        Title = "Read a file back off the host",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Read a file off the machine hosting this server, returned as base64, without needing an SMB " +
        "share. This is the reverse of put_file and the way to retrieve what the server produced - the " +
        "dump capture_dump wrote, the .pml or .csv capture_activity wrote - without touching the admin " +
        "share. By default it may only read inside the directories this server owns (its own folder and " +
        "the artifact directory, which is where every capture lands); reading anywhere else requires the " +
        "server to have been started with WINDIAG_ALLOW_ARBITRARY_READ. " +
        "A file larger than one slice is fetched by walking offset forward until endOfFile is true, " +
        "appending each slice; ask for includeWholeFileHash on the last one and compare it against the " +
        "reassembled copy. Each slice also carries its own chunkSha256, so corruption is caught at the " +
        "slice rather than as an opaque mismatch at the end. " +
        "IMPORTANT: the bytes come back in the response, so they land in the caller's context - pulling " +
        "a multi-megabyte dump this way is enormous. Use tools/fetch-from-target.ps1, which drives this " +
        "same loop and streams straight to a local file.")]
    public GetFileResult GetFile(
        [Description(@"Path on the host to read, e.g. the path capture_dump or capture_activity returned")]
        string path,
        [Description("Byte offset to start at. Walk this forward to fetch a whole file. Default 0.")]
        long offset = 0,
        [Description("Bytes to return. Default 64 KB, capped at 4 MB (base64 costs a third again, and a 32-bit target encodes it in one piece).")]
        int length = 0,
        [Description("Also return the SHA-256 of the WHOLE file, to verify a reassembled copy. Rereads the file, so ask for it only on the last slice.")]
        bool includeWholeFileHash = false,
        CancellationToken cancellationToken = default)
    {
        var result = _sender.Read(
            new FileReadRequest(path, offset, length, includeWholeFileHash), cancellationToken);

        return new GetFileResult(Render(result), result);
    }

    internal static string Render(FileReadResult result)
    {
        var builder = new StringBuilder();

        builder.Append("Read ").Append(Count(result.Length))
            .Append(" bytes at offset ").Append(Count(result.Offset))
            .Append(" of ").Append(Count(result.TotalBytes))
            .Append(" from ").AppendLine(result.Path);

        builder.Append("This slice's SHA-256 ").AppendLine(result.ChunkSha256);

        if (result.Sha256 is { } whole)
        {
            builder.Append("Whole-file SHA-256 ").AppendLine(whole);
        }

        builder.Append(result.EndOfFile
            ? "This slice reaches the end of the file."
            : $"More follows: request offset {Count(result.Offset + result.Length)} for the next slice.");

        return builder.ToString().TrimEnd();
    }

    private static string Count(long value) => value.ToString("N0", CultureInfo.InvariantCulture);
}
