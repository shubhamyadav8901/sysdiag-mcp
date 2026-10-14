using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Diag.Mcp.Server.Files;

/// <summary>
/// Reads a file back off the target, confined to the server's own directories unless arbitrary read is
/// enabled.
/// </summary>
/// <remarks>
/// <para>The counterpart to <see cref="FileReceiver"/>, and it exists for the same reason: to
/// take SMB out of the loop. Until now everything the server PRODUCED -- a minidump, a Procmon trace --
/// came back only as a UNC path on the admin share, so retrieving it dragged in the whole
/// "System error 5" token-filtering dance that <c>put_file</c> had already removed from staging. Reading
/// rides the same authenticated HTTP the tools already use, sliced and hash-verified exactly as the
/// write side is.</para>
/// <para>Slices, not whole files: the bytes are base64-encoded on the way out, which costs a third
/// again, and a 32-bit target has to hold the encoded form in memory. The caller walks
/// <see cref="FileReadRequest.Offset"/> forward and asks for the whole-file hash on the last slice.</para>
/// <para><strong>The scope check is the security boundary</strong>, and it is the shared
/// <see cref="FileScope"/> so it cannot drift from the write side's, applied through <see cref="ReadScope"/>, which
/// every other tool that reads a file's contents also goes through. Reading outside a server-owned
/// directory is arbitrary read as the server's account -- on an elevated server that is exfiltration of
/// anything it can open -- so it is refused unless explicitly enabled.</para>
/// </remarks>
public sealed class FileSender : IFileSender
{
    /// <summary>Largest slice a single call will return, matching the write side's chunk size.</summary>
    /// <remarks>
    /// 4 MB raw is ~5.6 MB of base64. Proven on the 32-bit server, where a whole binary in one argument
    /// exhausted memory inside the JSON pipeline.
    /// </remarks>
    public const int MaxLength = 4 * 1024 * 1024;

    /// <summary>What a caller gets when it does not say. Small, because a slice lands in its context.</summary>
    public const int DefaultLength = 64 * 1024;

    private readonly FileTransferOptions _options;
    private readonly ILogger<FileSender> _logger;

    public FileSender(FileTransferOptions options, ILogger<FileSender> logger)
    {
        _options = options;
        _logger = logger;
    }

    public FileReadResult Read(FileReadRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var (full, scope) = ReadScope.Require(request.Path, "source path", _options);

        if (!File.Exists(full))
        {
            throw new FileTransferException(
                $"'{full}' does not exist on this machine. A tool that writes a file returns the path it " +
                "wrote; pass that verbatim.");
        }

        if (request.Offset < 0)
        {
            throw new FileTransferException($"Offset {request.Offset} is negative.");
        }

        var length = request.Length <= 0 ? DefaultLength : Math.Min(request.Length, MaxLength);

        try
        {
            using var stream = new FileStream(
                full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

            var total = stream.Length;

            if (request.Offset > total)
            {
                throw new FileTransferException(
                    $"Offset {request.Offset} is past the end of '{full}', which is {total} bytes.");
            }

            stream.Seek(request.Offset, SeekOrigin.Begin);

            var remaining = total - request.Offset;
            var take = (int)Math.Min(length, remaining);
            var buffer = new byte[take];
            stream.ReadExactly(buffer, 0, take);

            var endOfFile = request.Offset + take >= total;

            // Only when asked: it rereads the entire file, so doing it per slice would make a chunked
            // fetch quadratic. The caller asks on the last slice, which is where it can act on the answer.
            var wholeFileHash = request.IncludeWholeFileHash ? Sha256Hex(full) : null;

            _logger.LogInformation(
                "get_file read {Length} bytes at {Offset} of {Total} from {Path} ({Scope} scope)",
                take, request.Offset, total, full, scope);

            return new FileReadResult(
                Path: full,
                Offset: request.Offset,
                Length: take,
                TotalBytes: total,
                Content: buffer,
                ChunkSha256: Convert.ToHexString(SHA256.HashData(buffer)),
                Sha256: wholeFileHash,
                EndOfFile: endOfFile,
                Scope: scope);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new FileTransferException(
                $"Could not read '{full}': {ex.Message}. The file may be locked exclusively by another " +
                "process, or the account may lack read access. who_locks_path will say which.", ex);
        }
    }

    private static string Sha256Hex(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
}
