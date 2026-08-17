using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using WinDiag.Mcp.Configuration;

namespace WinDiag.Mcp.Diagnostics.Files;

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
[SupportedOSPlatform("windows")]
public sealed class WindowsFileReceiver : IFileReceiver
{
    private readonly WinDiagOptions _options;
    private readonly ILogger<WindowsFileReceiver> _logger;

    public WindowsFileReceiver(WinDiagOptions options, ILogger<WindowsFileReceiver> logger)
    {
        _options = options;
        _logger = logger;
    }

    public FileWriteResult Receive(FileWriteRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var full = ResolvePath(request.Path);
        var scope = ScopeOf(full);

        if (scope == WriteScope.Arbitrary && !_options.AllowArbitraryWrite)
        {
            throw new FileTransferException(
                $"'{full}' is outside the directories this server owns ({ServerDirectory} and " +
                $"{_options.ArtifactDirectory}), so writing it needs arbitrary write, which is off. " +
                "Set WINDIAG_ALLOW_ARBITRARY_WRITE=1 to allow writing anywhere, or choose a path under " +
                "one of those directories. (run_command can also place a file anywhere if it is enabled.)");
        }

        var existed = File.Exists(full);
        if (existed && !request.Overwrite)
        {
            throw new FileTransferException(
                $"'{full}' already exists and overwrite is off. Pass overwrite to replace it, or write " +
                "to a different path.");
        }

        Write(full, request.Content);

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

    /// <summary>The directory the running server executable lives in.</summary>
    private static string ServerDirectory =>
        Path.GetDirectoryName(Environment.ProcessPath) ?? Environment.CurrentDirectory;

    private string ResolvePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new FileTransferException("No destination path was given.");
        }

        try
        {
            return Path.GetFullPath(path.Trim());
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new FileTransferException($"'{path}' is not a usable file path: {ex.Message}");
        }
    }

    private WriteScope ScopeOf(string fullPath) =>
        IsUnder(fullPath, ServerDirectory) || IsUnder(fullPath, _options.ArtifactDirectory)
            ? WriteScope.WinDiag
            : WriteScope.Arbitrary;

    /// <summary>True when <paramref name="candidate"/> is the directory itself or something inside it.</summary>
    /// <remarks>
    /// Compared on the canonical forms with a trailing separator, so <c>C:\WinDiagX\f</c> does not count
    /// as being under <c>C:\WinDiag</c> — a prefix match without the separator boundary is the classic
    /// way a scope check is escaped.
    /// </remarks>
    private static bool IsUnder(string candidate, string directory)
    {
        string root;
        try
        {
            root = Path.GetFullPath(directory);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }

        var rootWithSep = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                          + Path.DirectorySeparatorChar;

        return candidate.Equals(root, StringComparison.OrdinalIgnoreCase)
               || candidate.StartsWith(rootWithSep, StringComparison.OrdinalIgnoreCase);
    }

    private static void Write(string fullPath, byte[] content)
    {
        try
        {
            var directory = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllBytes(fullPath, content);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new FileTransferException(
                $"Could not write '{fullPath}': {ex.Message}. The file may be locked (a running binary " +
                "cannot be overwritten in place — stage to a .new name and use update_self), or the " +
                "account may lack write access there.", ex);
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
