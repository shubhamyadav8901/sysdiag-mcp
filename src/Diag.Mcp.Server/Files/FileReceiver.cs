using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Diag.Mcp.Server.Files;

/// <summary>
/// Writes a received file to disk, confined to windiag's own directories unless arbitrary write is
/// enabled.
/// </summary>
/// <remarks>
/// <para>This exists to take SMB out of the steady-state deployment loop. Staging an updated server
/// binary for <c>update_self</c>, staging the Sysinternals binaries, dropping a small input — all of
/// that previously travelled over the admin share, which is where the "System error 5" token-filtering
/// dance and the 89&#160;MB silent-corruption both lived. Over this channel the transfer rides the same
/// authenticated HTTP the tools already use, and is hash-verified on receipt.</para>
/// <para>The scope check is the security boundary. A write lands freely only inside a directory windiag
/// already owns — its own folder or the artifact directory — because that grants nothing that
/// SMB-to-those-folders plus <c>update_self</c> did not already allow. Anywhere else is arbitrary write
/// as the server's account, one step from code execution, and is refused unless explicitly enabled.
/// The path is canonicalised with <see cref="Path.GetFullPath(string)"/> first, so a <c>..</c> that
/// climbs out of an owned directory is judged by where it actually lands, not by how it was spelled.</para>
/// </remarks>
public sealed class FileReceiver : IFileReceiver
{
    private readonly FileTransferOptions _options;
    private readonly ILogger<FileReceiver> _logger;

    public FileReceiver(FileTransferOptions options, ILogger<FileReceiver> logger)
    {
        _options = options;
        _logger = logger;
    }

    public FileWriteResult Receive(FileWriteRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var full = FileScope.Resolve(request.Path, "destination path");
        var scope = FileScope.Of(full, _options);

        if (scope == WriteScope.Arbitrary && !_options.AllowArbitraryWrite)
        {
            throw new FileTransferException(
                $"'{full}' is outside the directories this server owns ({FileScope.Describe(_options)}), " +
                "so writing it needs arbitrary write, which is off. " +
                $"Set {_options.ArbitraryWriteSetting} to allow writing anywhere, or choose a path under " +
                "one of those directories. (run_command can also place a file anywhere if it is enabled.)");
        }

        // Checked in memory before any disk write, so a chunk corrupted on a lossy link is rejected at
        // the chunk -- and because nothing has been written, the file is untouched and the caller can
        // re-send that chunk safely.
        if (request.ChunkSha256 is { } chunkExpected)
        {
            var chunkSha = Convert.ToHexString(SHA256.HashData(request.Content));
            if (!chunkSha.Equals(chunkExpected.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                throw new FileTransferException(
                    $"This chunk arrived corrupted (SHA-256 {chunkSha}, expected {chunkExpected}). " +
                    "Nothing was written; re-send it.");
            }
        }

        var existed = File.Exists(full);
        if (existed && !request.Overwrite && !request.Append)
        {
            throw new FileTransferException(
                $"'{full}' already exists and overwrite is off. Pass overwrite to replace it, or write " +
                "to a different path.");
        }

        if (request.Append)
        {
            Append(full, request.Content);
        }
        else
        {
            Write(full, request.Content);
        }

        // Verify only when a hash is given. For a chunked send that is the last chunk, and the hash is
        // of the assembled whole -- so this reads the finished file off disk (streaming, low memory) and
        // checks it, catching a bad chunk anywhere in the sequence.
        var sha = Sha256Hex(full);
        if (request.ExpectedSha256 is { } expected && !sha.Equals(expected.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            // The same rollback the SMB path relied on: a transfer that did not arrive intact leaves no
            // half-written file behind to be mistaken for a good one.
            TryDelete(full);
            throw new FileTransferException(
                $"'{full}' was written but its SHA-256 is {sha}, not the expected {expected}. The file " +
                "has been deleted; nothing partial was left in place. Re-send it.");
        }

        _logger.LogInformation(
            "put_file wrote {SizeBytes} bytes to {Path} ({Scope} scope, sha {Sha})",
            request.Content.LongLength, full, scope, sha);

        return new FileWriteResult(full, request.Content.LongLength, sha, scope, existed);
    }

    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private const UnixFileMode OwnerOnlyDirectory = OwnerOnly | UnixFileMode.UserExecute;

    private static void Write(string fullPath, byte[] content)
    {
        try
        {
            EnsureDirectory(fullPath);

            if (OperatingSystem.IsWindows())
            {
                File.WriteAllBytes(fullPath, content);
                return;
            }

            // Cleared first: deleting a link removes the link, not what it points at. Recreated with
            // CreateNew, which is O_EXCL -- it cannot follow a link and fails if one reappears -- and born
            // 0600, so a file replacing a loose one never inherits its mode. The same pattern as the
            // relay's partial files, for the same reason: this process may be root.
            File.Delete(fullPath);
            using var stream = new FileStream(fullPath, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                UnixCreateMode = OwnerOnly,
            });
            stream.Write(content, 0, content.Length);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new FileTransferException(
                $"Could not write '{fullPath}': {ex.Message}. The file may be locked (a running binary " +
                "cannot be overwritten in place — stage to a .new name and use update_self), or the " +
                "account may lack write access there.", ex);
        }
    }

    private static void Append(string fullPath, byte[] content)
    {
        // Every chunk after the first lands here. Off Windows a destination that has become a link since
        // the first chunk is refused rather than followed; FileStream has no O_NOFOLLOW, so it is checked
        // first, which narrows the window to the instant between the check and the open.
        if (!OperatingSystem.IsWindows() && new FileInfo(fullPath).LinkTarget is not null)
        {
            throw new FileTransferException(
                $"'{fullPath}' is a symbolic link, so this chunk was not appended. Start the transfer over.");
        }

        try
        {
            EnsureDirectory(fullPath);

            // An append creates a missing file, so off Windows it is born 0600 like any other write --
            // left to the umask, a root service's appends would be world-readable. The mode applies only
            // when the file is created; an existing file keeps its own.
            var options = new FileStreamOptions { Mode = FileMode.Append, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = OwnerOnly;
            }

            using var stream = new FileStream(fullPath, options);
            stream.Write(content, 0, content.Length);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new FileTransferException(
                $"Could not append to '{fullPath}': {ex.Message}. If a previous chunked transfer was " +
                "interrupted, delete the partial file and start over.", ex);
        }
    }

    private static void EnsureDirectory(string fullPath)
    {
        var directory = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrEmpty(directory))
        {
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(directory);
        }
        else
        {
            // Only directories this creates get the mode; an existing one is left as the operator set it.
            Directory.CreateDirectory(directory, OwnerOnlyDirectory);
        }
    }

    private static string Sha256Hex(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort. The mismatch is already being reported; a lingering bad file is the lesser
            // problem and the caller has been told the hash did not match.
        }
    }
}
