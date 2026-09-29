using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using ModelContextProtocol.Protocol;

namespace DiagRelay.Mcp;

/// <summary>Calls one tool on an already-connected target.</summary>
/// <remarks>
/// A delegate rather than <see cref="RelayState"/> itself, so the transfer loops can be driven by a
/// fake in tests. The loops are the part worth testing -- chunk boundaries, the retry, the hash checks --
/// and none of that should need a live Windows target to exercise.
/// </remarks>
internal delegate Task<CallToolResult> ForwardTool(
    string tool, IReadOnlyDictionary<string, object?> arguments, CancellationToken cancellationToken);

/// <summary>
/// Moves whole files between this machine and a target, over the target's own put_file/get_file.
/// </summary>
/// <remarks>
/// <para>This exists so that a transfer costs the caller a tool call and not a payload. Driving put_file
/// directly from an agent session means every byte is a token the model has to emit: a 46 MB build is
/// ~63 MB of base64, which no context holds and no budget wants. Here the bytes are read from local disk
/// by the relay process and streamed to the target; the model sends a path and gets back a summary line.
/// The same reasoning already applies in the other direction, which is why get_file's own description
/// points at a script instead of itself.</para>
/// <para>Neither loop holds the file in memory. Both verify every chunk in flight and the whole file at
/// the end, because the failure this guards against is silent: an 89 MB SMB copy to a lab VM was seen
/// truncating at exactly the right size, and a 32-bit target answers a wrongly-sized read without
/// complaint.</para>
/// </remarks>
internal static class RelayFileTransfer
{
    /// <summary>
    /// Bytes per call. 4 MB raw is ~5.6 MB of base64, which is the server's own per-call cap and what a
    /// 32-bit target can decode in one piece.
    /// </summary>
    public const int ChunkBytes = 4 * 1024 * 1024;

    /// <summary>
    /// Attempts per chunk before the transfer is abandoned.
    /// </summary>
    /// <remarks>
    /// Per chunk, not per transfer: a refused chunk is re-sent on its own rather than restarting a
    /// 46 MB upload from zero, which is what made a lossy link to a lab VM practical at all.
    /// </remarks>
    public const int ChunkAttempts = 3;

    public sealed record PushOutcome(
        string LocalPath, string RemotePath, long Bytes, int Chunks, string Sha256, int Retries);

    public sealed record PullOutcome(
        string RemotePath, string LocalPath, long Bytes, int Slices, string Sha256, bool VerifiedAgainstTarget);

    /// <summary>Sends a local file to the target, in hash-verified chunks.</summary>
    public static async Task<PushOutcome> PushAsync(
        ForwardTool forward,
        string localFullPath,
        string remotePath,
        bool overwrite,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(localFullPath))
        {
            throw new RelayException($"There is no file at '{localFullPath}' to send.");
        }

        var length = new FileInfo(localFullPath).Length;
        var wholeHash = await FileHashAsync(localFullPath, cancellationToken).ConfigureAwait(false);

        await using var source = new FileStream(
            localFullPath, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkBytes, useAsync: true);

        var buffer = new byte[ChunkBytes];
        var chunks = 0;
        var retries = 0;
        long sent = 0;

        // A zero-byte file still needs one call, or nothing is created on the target at all.
        do
        {
            var read = await ReadBlockAsync(source, buffer, cancellationToken).ConfigureAwait(false);
            var payload = new ReadOnlyMemory<byte>(buffer, 0, read);
            var last = sent + read >= length;

            var arguments = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["path"] = remotePath,
                ["contentBase64"] = Convert.ToBase64String(payload.Span),
                ["append"] = chunks > 0,
                ["chunkSha256"] = Hex(SHA256.HashData(payload.Span))
            };

            // Only the first call decides whether an existing file is replaced; the rest append to what
            // it created, so passing it again would be meaningless at best.
            if (chunks == 0)
            {
                arguments["overwrite"] = overwrite;
            }

            // The whole-file hash goes on the last chunk, where the target can check the assembled file
            // and roll it back if it does not match.
            if (last)
            {
                arguments["expectedSha256"] = wholeHash;
            }

            retries += await SendChunkAsync(
                forward, arguments, chunks + 1, payload.Length, sent, cancellationToken).ConfigureAwait(false);

            chunks++;
            sent += read;
        }
        while (sent < length);

        return new PushOutcome(localFullPath, remotePath, length, chunks, wholeHash, retries);
    }

    /// <summary>Sends one chunk, re-sending it rather than the transfer when the target refuses it.</summary>
    /// <returns>How many retries this chunk cost, for a summary that does not hide a flaky link.</returns>
    private static async Task<int> SendChunkAsync(
        ForwardTool forward,
        IReadOnlyDictionary<string, object?> arguments,
        int number,
        int size,
        long offset,
        CancellationToken cancellationToken)
    {
        RelayException? failure = null;

        for (var attempt = 1; attempt <= ChunkAttempts; attempt++)
        {
            try
            {
                var result = await forward("put_file", arguments, cancellationToken).ConfigureAwait(false);
                if (result.IsError != true)
                {
                    return attempt - 1;
                }

                failure = new RelayException(
                    $"chunk {number} ({size:N0} bytes at {offset:N0}) was refused: {TextOf(result)}");
            }
            catch (RelayException ex)
            {
                failure = ex;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }

        throw new RelayException(
            $"Giving up after {ChunkAttempts} attempts at chunk {number}. {failure?.Message} " +
            "Nothing was rolled back on the target: the partial file is still there under the destination " +
            "name, so re-run this push to overwrite it rather than assuming the target is untouched.");
    }

    /// <summary>Reads a whole file back from the target and streams it to local disk.</summary>
    public static async Task<PullOutcome> PullAsync(
        ForwardTool forward,
        string remotePath,
        string localFullPath,
        bool overwrite,
        CancellationToken cancellationToken)
    {
        if (File.Exists(localFullPath) && !overwrite)
        {
            throw new RelayException(
                $"'{localFullPath}' already exists. Pass overwrite=true to replace it, or choose another name.");
        }

        var directory = Path.GetDirectoryName(localFullPath);
        if (!string.IsNullOrEmpty(directory))
        {
            // Owner-only off Windows: a pull is a dump or a trace, and a directory created under the
            // default umask would be listable, and its files readable, by every local user.
            if (OperatingSystem.IsWindows())
            {
                Directory.CreateDirectory(directory);
            }
            else
            {
                Directory.CreateDirectory(
                    directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
        }

        // Written to a temporary name and moved into place at the end, so an interrupted pull cannot
        // leave a short file sitting at the name the caller will go on to use.
        var partial = localFullPath + ".partial";

        long offset = 0;
        long total = -1;
        var slices = 0;
        string? reportedWholeHash = null;

        try
        {
            await using (var destination = OpenPartial(partial))
            {
                while (true)
                {
                    var arguments = new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["path"] = remotePath,
                        ["offset"] = offset,
                        ["length"] = ChunkBytes,

                        // Asked once, on the first call: it rereads the whole file on the target, and the
                        // answer does not change under us for a file nobody is writing.
                        ["includeWholeFileHash"] = slices == 0
                    };

                    var result = await forward("get_file", arguments, cancellationToken).ConfigureAwait(false);
                    if (result.IsError == true)
                    {
                        throw new RelayException($"Reading '{remotePath}' failed: {TextOf(result)}");
                    }

                    var file = Slice(result, remotePath);
                    total = total < 0 ? file.TotalBytes : total;
                    reportedWholeHash ??= file.WholeSha256;

                    var actual = Hex(SHA256.HashData(file.Content));
                    if (!string.Equals(actual, file.ChunkSha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new RelayException(
                            $"The slice at {offset:N0} arrived corrupted: the target hashed it as " +
                            $"{file.ChunkSha256}, it arrived as {actual}. Nothing was kept.");
                    }

                    await destination.WriteAsync(file.Content, cancellationToken).ConfigureAwait(false);

                    offset += file.Content.Length;
                    slices++;

                    if (file.EndOfFile)
                    {
                        break;
                    }

                    if (file.Content.Length == 0)
                    {
                        // Neither at the end nor making progress: stop rather than loop forever.
                        throw new RelayException(
                            $"The target returned an empty slice at {offset:N0} without reporting the end of " +
                            $"'{remotePath}'. Nothing was kept.");
                    }
                }
            }

            var wrote = new FileInfo(partial).Length;
            if (total >= 0 && wrote != total)
            {
                throw new RelayException(
                    $"Reassembled {wrote:N0} bytes but the target reported {total:N0}. Nothing was kept.");
            }

            var localHash = await FileHashAsync(partial, cancellationToken).ConfigureAwait(false);
            var verified = reportedWholeHash is not null;

            if (verified && !string.Equals(localHash, reportedWholeHash, StringComparison.OrdinalIgnoreCase))
            {
                throw new RelayException(
                    $"The reassembled copy hashes to {localHash} but the target reported " +
                    $"{reportedWholeHash}. Nothing was kept.");
            }

            File.Move(partial, localFullPath, overwrite: true);
            return new PullOutcome(remotePath, localFullPath, wrote, slices, localHash, verified);
        }
        catch
        {
            TryDelete(partial);
            throw;
        }
    }

    private sealed record FileSlice(
        byte[] Content, string ChunkSha256, long TotalBytes, bool EndOfFile, string? WholeSha256);

    /// <summary>Pulls one slice out of a get_file response, insisting on the fields it must carry.</summary>
    /// <summary>Opens the temporary file a pull writes into, owner-only and never through a link.</summary>
    /// <remarks>
    /// FileMode.Create follows a symlink and keeps an existing file's mode, so a link planted at
    /// <c>name.partial</c> -- by anyone who can write the destination directory -- turned a pull into an
    /// overwrite of a file of their choosing, with the operator's rights. Off Windows the name is cleared
    /// first (deleting a link removes the link, not what it points at) and recreated with CreateNew,
    /// which is O_EXCL: it cannot follow a link and fails if one reappears, and it is born 0600.
    /// </remarks>
    private static FileStream OpenPartial(string partial)
    {
        if (OperatingSystem.IsWindows())
        {
            return new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None, ChunkBytes, useAsync: true);
        }

        File.Delete(partial);
        return new FileStream(partial, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            BufferSize = ChunkBytes,
            Options = FileOptions.Asynchronous,
            UnixCreateMode = RelayTargetsFile.OwnerOnly,
        });
    }

    private static FileSlice Slice(CallToolResult result, string remotePath)
    {
        if (result.StructuredContent is not { } root
            || root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("file", out var file)
            || file.ValueKind != JsonValueKind.Object)
        {
            throw new RelayException(
                $"The target's get_file answer for '{remotePath}' carried no file object. It may be running " +
                "a build without get_file; reconnect after updating it.");
        }

        var content = String(file, "content")
            ?? throw new RelayException($"The get_file answer for '{remotePath}' carried no content.");
        var chunkSha = String(file, "chunkSha256")
            ?? throw new RelayException(
                $"The get_file answer for '{remotePath}' carried no chunkSha256, so the slice cannot be " +
                "verified. Refusing rather than trusting it.");

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(content);
        }
        catch (FormatException ex)
        {
            throw new RelayException($"The slice of '{remotePath}' was not valid base64: {ex.Message}");
        }

        var total = file.TryGetProperty("totalBytes", out var t) && t.TryGetInt64(out var parsed) ? parsed : -1;
        var end = file.TryGetProperty("endOfFile", out var e) && e.ValueKind == JsonValueKind.True;

        return new FileSlice(bytes, chunkSha, total, end, String(file, "sha256"));
    }

    private static string? String(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    /// <summary>Fills the buffer as far as the file allows, since one read may return less.</summary>
    private static async Task<int> ReadBlockAsync(
        Stream source, byte[] buffer, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await source.ReadAsync(buffer.AsMemory(total), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }

    private static async Task<string> FileHashAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkBytes, useAsync: true);

        return Hex(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
    }

    private static string Hex(byte[] hash) => Convert.ToHexString(hash);

    private static string TextOf(CallToolResult result)
    {
        var text = result.Content?.OfType<TextContentBlock>().Select(b => b.Text).FirstOrDefault();
        return string.IsNullOrWhiteSpace(text) ? "the target gave no reason" : text.Trim();
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"[windiag-relay] could not remove the partial file {path}: {ex.Message}");
        }
    }

    /// <summary>Formats a byte count the same way in every locale.</summary>
    /// <remarks>
    /// InvariantCulture on purpose: on a machine set to en-IN, "N0" renders 2,208,024 as "22,08,024".
    /// A byte count is read against the file, not against local convention -- the same reason
    /// fetch-from-target.ps1 pins it.
    /// </remarks>
    public static string Bytes(long value) => value.ToString("N0", CultureInfo.InvariantCulture);
}
