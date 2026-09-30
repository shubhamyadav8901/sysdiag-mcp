
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
    public static WriteScope Of(string fullPath, FileTransferOptions options) =>
        Of(fullPath, options, ServerDirectory);

    internal static WriteScope Of(string fullPath, FileTransferOptions options, string serverDirectory) =>
        Classify(fullPath, options, serverDirectory).Scope;

    /// <summary>
    /// The scope, and whether the path lands in the server's own directory rather than the artifact
    /// directory -- from one resolution, so the two answers are about the same real path.
    /// </summary>
    /// <remarks>
    /// <para>The server directory is resolved the same way as the path, so a link cannot get around the
    /// comparison from either side.</para>
    /// <para>Every real path under the server directory counts as in it, wherever the artifact directory
    /// is. One above it (<c>/opt</c>, <c>/</c>) or equal to it made the server's own binary writable with
    /// no grant when "under the artifacts" was an exemption; one nested inside it did the same for
    /// whatever it held. The published binary's RUNPATH is <c>$ORIGIN/netcoredeps</c>, so an artifact
    /// directory of <c>/opt/linuxdiag/netcoredeps</c> would have made a directory a root process loads
    /// libraries from writable with only the token.</para>
    /// </remarks>
    /// <param name="replacesFinalLink">
    /// The operation replaces a link at the last component instead of following it, so it is judged at
    /// the link's own location: see <see cref="LandingPath"/>.
    /// </param>
    internal static (WriteScope Scope, bool InServerDirectory) Classify(
        string fullPath, FileTransferOptions options, string serverDirectory, bool replacesFinalLink = false)
    {
        var real = LandingPath(fullPath, replacesFinalLink);
        var server = RealPath(serverDirectory);
        var artifacts = RealPath(options.ArtifactDirectory);
        var inServer = IsUnder(real, server);
        return (inServer || IsUnder(real, artifacts) ? WriteScope.WinDiag : WriteScope.Arbitrary, inServer);
    }

    /// <summary>The real path an operation on <paramref name="fullPath"/> touches.</summary>
    /// <remarks>
    /// A read, an append and a Windows write follow a link at the last component, so they touch its
    /// target. A Unix write unlinks the destination and creates a new file in its place, so a link
    /// there is replaced where it sits: only the parent directories are followed, and the name is kept
    /// as spelled. Judging that write at the link's target let <c>/tmp/x -&gt; /var/lib/linuxdiag/x</c>
    /// pass as owned while root created <c>/tmp/x</c>.
    /// </remarks>
    internal static string LandingPath(string fullPath, bool replacesFinalLink)
    {
        var name = Path.GetFileName(fullPath);
        var parent = Path.GetDirectoryName(fullPath);
        return replacesFinalLink && !string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(parent)
            ? Path.Combine(RealPath(parent), name)
            : RealPath(fullPath);
    }

    /// <summary>How many links one resolution may follow before it is called a loop: the kernel's own limit.</summary>
    internal const int MaxLinkHops = 40;

    /// <summary>The path with every link in every existing component resolved, like realpath(3).</summary>
    /// <remarks>
    /// <para>
    /// Walked one component at a time, the way the kernel walks it. A link's target is spliced into
    /// the components still to come, and a <c>..</c> climbs from the directory resolved so far, never
    /// from the spelling. Collapsing a target's <c>..</c> as spelled -- which is what
    /// <c>ResolveLinkTarget</c> and <c>GetFullPath</c> do -- judged <c>hop/..</c> as the directory
    /// holding <c>hop</c>, while the kernel went through <c>hop</c> first and landed somewhere else.
    /// </para>
    /// <para>
    /// Iterative, with a hop budget, rather than recursing on each target: a loop through a parent
    /// component is invisible to <c>ResolveLinkTarget</c>, and the recursion it caused ran until the
    /// stack overflowed and took the whole server down. Every failure here -- a loop, an unreadable
    /// link -- is the refusal the caller sees.
    /// </para>
    /// <para>
    /// Components that do not exist yet -- the file about to be written, a directory about to be made --
    /// are kept as spelled, since there is nothing there to be a link.
    /// </para>
    /// </remarks>
    internal static string RealPath(string fullPath) =>
        RealPath(fullPath, path => LinkTargetOf(path, fullPath), relativeTargetsBySpelling: OperatingSystem.IsWindows());

    /// <summary>The walk itself, with the link lookup and the OS's rule for relative targets supplied.</summary>
    /// <param name="linkTargetOf">The raw target of the link at a path, or null when it is not a link.</param>
    /// <param name="relativeTargetsBySpelling">Windows' rule for a relative link target, rather than POSIX's.</param>
    internal static string RealPath(string fullPath, Func<string, string?> linkTargetOf, bool relativeTargetsBySpelling)
    {
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root))
        {
            return fullPath;
        }

        var current = root;
        var pending = new Stack<string>();
        PushComponents(pending, fullPath[root.Length..]);
        var hops = 0;

        while (pending.Count > 0)
        {
            var part = pending.Pop();
            if (part == ".")
            {
                continue;
            }

            if (part == "..")
            {
                // The parent of a root is the root, as it is to the kernel.
                current = Path.GetDirectoryName(current) ?? current;
                continue;
            }

            var next = Path.Combine(current, part);
            var target = linkTargetOf(next);
            if (target is null)
            {
                current = next;
                continue;
            }

            if (++hops > MaxLinkHops)
            {
                throw new FileTransferException(
                    $"'{fullPath}' could not be resolved: it passes through more than {MaxLinkHops} links, " +
                    "which is a link loop.");
            }

            // Windows and POSIX disagree on a relative target. The NT I/O manager joins it onto the
            // link's directory and collapses its '..' by spelling, never going through the links the
            // target names; POSIX walks those components like any others. Walking on Windows judged
            // 'hop\..\..' by where hop points, while Windows opened the directory two levels up.
            if (relativeTargetsBySpelling && !Path.IsPathRooted(target))
            {
                target = Path.GetFullPath(Path.Combine(current, target));
            }

            // An absolute target starts again from its own root; a relative one carries on from the
            // directory holding the link, which is where the walk already is.
            var targetRoot = Path.GetPathRoot(target);
            if (!string.IsNullOrEmpty(targetRoot))
            {
                current = Path.GetPathRoot(Path.GetFullPath(targetRoot, current))!;
            }

            PushComponents(pending, target[(targetRoot?.Length ?? 0)..]);
        }

        return current;
    }

    /// <summary>The raw target of the link at <paramref name="path"/>, or null when it is not a link or does not exist.</summary>
    private static string? LinkTargetOf(string path, string fullPath)
    {
        try
        {
            FileSystemInfo info = Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path);
            return info.LinkTarget;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // An unreadable link cannot be judged, so it is refused rather than let through as spelled.
            throw new FileTransferException($"'{fullPath}' could not be resolved: {ex.Message}");
        }
    }

    /// <summary>Pushes the components of <paramref name="relative"/> so that the first one is popped first.</summary>
    private static void PushComponents(Stack<string> pending, string relative)
    {
        var parts = relative.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries);
        for (var i = parts.Length - 1; i >= 0; i--)
        {
            pending.Push(parts[i]);
        }
    }

    /// <summary>Names the owned directories, for an error message that says where a path *would* be allowed.</summary>
    public static string Describe(FileTransferOptions options) => Describe(options, ServerDirectory);

    internal static string Describe(FileTransferOptions options, string serverDirectory) =>
        $"{serverDirectory} and {options.ArtifactDirectory}";

    /// <summary>True when <paramref name="candidate"/> is the directory itself or something inside it.</summary>
    /// <remarks>Delegates, so the server and the relay can never disagree about containment.</remarks>
    public static bool IsUnder(string candidate, string directory) => PathScope.IsUnder(candidate, directory);
}
