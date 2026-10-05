using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Diag.Mcp.Server.Files;

/// <summary>
/// Writes a received file to disk, confined to the server's own directories unless arbitrary write is
/// enabled.
/// </summary>
/// <remarks>
/// <para>This exists to take SMB out of the steady-state deployment loop. Staging an updated server
/// binary for <c>update_self</c>, staging the Sysinternals binaries, dropping a small input — all of
/// that previously travelled over the admin share, which is where the "System error 5" token-filtering
/// dance and the 89&#160;MB silent-corruption both lived. Over this channel the transfer rides the same
/// authenticated HTTP the tools already use, and is hash-verified on receipt.</para>
/// <para>The scope check is the security boundary. A write lands freely only inside a directory the server
/// already owns — its own folder or the artifact directory — because that grants nothing that
/// SMB-to-those-folders plus <c>update_self</c> did not already allow. Anywhere else is arbitrary write
/// as the server's account, one step from code execution, and is refused unless explicitly enabled.
/// A server may also close its own folder unless its self-update grant is on
/// (<see cref="FileTransferOptions.ServerDirectoryWritable"/>): LinuxDiag does, windiag does not.
/// The path is canonicalised with <see cref="Path.GetFullPath(string)"/> first, and its links resolved,
/// so a <c>..</c> or a link that climbs out of an owned directory is judged by where the write actually
/// lands, not by how it was spelled -- including a link at the last component, which a Unix write
/// replaces rather than follows (<see cref="FileScope.LandingPath"/>).</para>
/// </remarks>
public sealed class FileReceiver : IFileReceiver
{
    private readonly FileTransferOptions _options;
    private readonly ILogger<FileReceiver> _logger;
    private readonly string _serverDirectory;

    public FileReceiver(FileTransferOptions options, ILogger<FileReceiver> logger)
        : this(options, logger, FileScope.ServerDirectory)
    {
    }

    /// <summary>For tests: under <c>dotnet test</c> the process directory is the SDK's, not a server's.</summary>
    internal FileReceiver(FileTransferOptions options, ILogger<FileReceiver> logger, string serverDirectory)
    {
        _options = options;
        _logger = logger;
        _serverDirectory = serverDirectory;
    }

    public FileWriteResult Receive(FileWriteRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var full = FileScope.Resolve(request.Path, "destination path");

        // Both answers come from where the bytes will land. Off Windows, Write replaces a link at the
        // destination rather than following it, so that write is judged at the link, not its target.
        var replacesFinalLink = !OperatingSystem.IsWindows() && !request.Append;
        var (scope, inServerDirectory) = FileScope.Classify(full, _options, _serverDirectory, replacesFinalLink);

        if (scope == WriteScope.Arbitrary && !_options.AllowArbitraryWrite)
        {
            // Where the server reserves its own folder, "one of those directories" would send the caller
            // straight into the next refusal, so it names the one that is open and what the other needs.
            var alternative = _options.ServerDirectoryWritable
                ? "one of those directories"
                : $"{_options.ArtifactDirectory} (writing under {_serverDirectory} also needs " +
                  $"{_options.ServerDirectorySetting})";
            throw new FileTransferException(
                $"'{full}' is outside the directories this server owns ({FileScope.Describe(_options, _serverDirectory)}), " +
                "so writing it needs arbitrary write, which is off. " +
                $"Set {_options.ArbitraryWriteSetting} to allow writing anywhere, or choose a path under " +
                $"{alternative}. (run_command can also place a file anywhere if it is enabled.)");
        }

        // Staging a build for update_self is the only reason to write beside the server's binary, and on
        // Linux that binary is a root service's: a planted file there is loaded or run as root. So a
        // server that says so ties the write to the self-update grant; windiag leaves it open, as it
        // always has. Checked before any disk write, so an append chunk is refused the same way.
        if (inServerDirectory && !_options.ServerDirectoryWritable && !_options.AllowArbitraryWrite)
        {
            throw new FileTransferException(
                $"'{full}' is in this server's own directory ({_serverDirectory}), and writing there is " +
                "only for staging a build for update_self, which is off. " +
                $"Set {_options.ServerDirectorySetting} to allow it (or {_options.ArbitraryWriteSetting} to " +
                $"allow writing anywhere), or choose a path under {_options.ArtifactDirectory}.");
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
            // relay's partial files, for the same reason: this process may be root. Because a link here
            // is replaced where it sits, Receive judges this write at the link, not at its target; the
            // two must change together.
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
                "cannot be overwritten in place — stage it under a new name and use update_self), or the " +
                "account may lack write access there.", ex);
        }
    }

    private static void Append(string fullPath, byte[] content)
    {
        // Every chunk after the first lands here, and a destination that has become a link since the
        // first chunk must be refused rather than followed. On x86-64 Linux open(2) itself refuses it,
        // in the same system call that opens: no window between checking and opening. macOS does the
        // same through its own flags and a two-argument open; MacNoFollow says why it is not one class.
        if (OperatingSystem.IsMacOS())
        {
            try
            {
                EnsureDirectory(fullPath);
                MacNoFollow.Append(fullPath, content);
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new FileTransferException(
                    $"Could not append to '{fullPath}': {ex.Message}. If a previous chunked transfer was " +
                    "interrupted, delete the partial file and start over.", ex);
            }
        }

        if (OperatingSystem.IsLinux() && LinuxNoFollow.Supported)
        {
            try
            {
                EnsureDirectory(fullPath);
                using var noFollow = LinuxNoFollow.OpenForAppend(fullPath);
                noFollow.Write(content, 0, content.Length);
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new FileTransferException(
                    $"Could not append to '{fullPath}': {ex.Message}. If a previous chunked transfer was " +
                    "interrupted, delete the partial file and start over.", ex);
            }
        }

        // The fallback, for every other Unix: FileStream has no O_NOFOLLOW, so the link is checked first,
        // which narrows the window to the instant between the check and the open.
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
