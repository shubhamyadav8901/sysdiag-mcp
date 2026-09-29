
namespace Diag.Mcp.Server.Files;

/// <summary>
/// Decides whether a path is inside a directory windiag owns. Shared by both directions of transfer.
/// </summary>
/// <remarks>
/// This is the security boundary for <c>put_file</c> and <c>get_file</c> alike, and it is deliberately
/// one implementation rather than two: a scope check that is copied is a scope check that drifts, and
/// the read side inherits exactly the containment the write side was reviewed for. The path is
/// canonicalised first, so a <c>..</c> that climbs out of an owned directory is judged by where it
/// actually lands, not by how it was spelled.
/// </remarks>
internal static class FileScope
{
    /// <summary>The directory the running server executable lives in.</summary>
    public static string ServerDirectory => PathScope.ProcessDirectory;

    /// <summary>Canonicalises a caller-supplied path, or explains why it is unusable.</summary>
    public static string Resolve(string? path, string what) => PathScope.Resolve(path, what);

    /// <summary>Whether the path, as it really resolves, sits inside a server-owned directory.</summary>
    /// <remarks>
    /// Judged on real paths, on both sides. A lexical check alone let a link planted inside an owned
    /// directory -- a symlink on Linux, a junction on Windows -- carry a write or a read anywhere the
    /// link pointed, while every path in the request still looked owned.
    /// </remarks>
    public static WriteScope Of(string fullPath, FileTransferOptions options)
    {
        var real = RealPath(fullPath);
        return IsUnder(real, RealPath(ServerDirectory)) || IsUnder(real, RealPath(options.ArtifactDirectory))
            ? WriteScope.WinDiag
            : WriteScope.Arbitrary;
    }

    /// <summary>The path with every link in every existing component resolved, like realpath(3).</summary>
    /// <remarks>
    /// Components that do not exist yet -- the file about to be written, a directory about to be made --
    /// are kept as spelled, since there is nothing there to be a link. A link loop surfaces as the
    /// refusal the caller sees, not as an unreadable error.
    /// </remarks>
    internal static string RealPath(string fullPath)
    {
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root))
        {
            return fullPath;
        }

        var current = root;
        var parts = fullPath[root.Length..].Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries);

        foreach (var part in parts)
        {
            var next = Path.Combine(current, part);
            FileSystemInfo info = Directory.Exists(next) ? new DirectoryInfo(next) : new FileInfo(next);

            FileSystemInfo? target;
            try
            {
                target = info.LinkTarget is null ? null : info.ResolveLinkTarget(returnFinalTarget: true);
            }
            catch (IOException ex)
            {
                throw new FileTransferException($"'{fullPath}' could not be resolved: {ex.Message}");
            }

            // The final target's own parents may be links too, so it is resolved again from the top.
            current = target is null ? next : RealPath(Path.GetFullPath(target.FullName));
        }

        return current;
    }

    /// <summary>Names the owned directories, for an error message that says where a path *would* be allowed.</summary>
    public static string Describe(FileTransferOptions options) =>
        $"{ServerDirectory} and {options.ArtifactDirectory}";

    /// <summary>True when <paramref name="candidate"/> is the directory itself or something inside it.</summary>
    /// <remarks>Delegates, so the server and the relay can never disagree about containment.</remarks>
    public static bool IsUnder(string candidate, string directory) => PathScope.IsUnder(candidate, directory);
}
