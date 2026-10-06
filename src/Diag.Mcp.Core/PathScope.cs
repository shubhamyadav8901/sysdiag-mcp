namespace Diag.Mcp.Core;

/// <summary>
/// Canonicalises paths and decides whether one sits inside a directory: the containment half of every
/// file-transfer boundary in this family of tools.
/// </summary>
/// <remarks>
/// One implementation, shared by the Windows server's put_file/get_file and the relay's push_file/
/// pull_file, because a scope check that is copied is a scope check that drifts. The path is
/// canonicalised first, so a <c>..</c> that climbs out of a directory is judged by where it actually
/// lands, not by how it was spelled.
/// </remarks>
public static class PathScope
{
    /// <summary>How paths compare on this OS: case-insensitively on Windows, case-sensitively elsewhere.</summary>
    /// <remarks>
    /// Case-sensitive on macOS too. APFS is case-insensitive by default but can be formatted
    /// case-sensitive, and on such a volume a case-insensitive check admits a directory that is not the
    /// root. This is a confinement boundary, so it fails closed: the cost on a default macOS volume is
    /// that a path typed in a different case from its root is refused.
    /// </remarks>
    public static StringComparison PathComparison { get; } =
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    /// <summary><see cref="PathComparison"/> as a comparer, for collections of paths.</summary>
    public static StringComparer PathComparer { get; } =
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    /// <summary>The directory this process's executable lives in.</summary>
    public static string ProcessDirectory =>
        Path.GetDirectoryName(Environment.ProcessPath) ?? Environment.CurrentDirectory;

    /// <summary>Canonicalises a caller-supplied path, or explains why it is unusable.</summary>
    public static string Resolve(string? path, string what)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new FileTransferException($"No {what} was given.");
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

    /// <summary>True when <paramref name="candidate"/> is the directory itself or something inside it.</summary>
    public static bool IsUnder(string candidate, string directory) =>
        IsUnder(candidate, directory, PathComparison);

    /// <summary>
    /// <see cref="IsUnder(string, string)"/> with the comparison chosen by the caller -- so the logic of
    /// both platforms' branches can be pinned by tests on either platform.
    /// </summary>
    /// <remarks>
    /// Compared on the canonical forms with a trailing separator, so <c>C:\WinDiagX\f</c> does not count
    /// as being under <c>C:\WinDiag</c> -- a prefix match without the separator boundary is the classic
    /// way a scope check is escaped.
    /// </remarks>
    public static bool IsUnder(string candidate, string directory, StringComparison comparison)
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

        return candidate.Equals(root, comparison) || candidate.StartsWith(rootWithSep, comparison);
    }

    /// <summary>How many links one resolution may follow before it is called a loop: the kernel's own limit.</summary>
    public const int MaxLinkHops = 40;

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
    /// <para>
    /// Here rather than in the server kit, which the relay must not reference: the relay's push_file and
    /// pull_file judge links with this same walk, not a second one that would drift from it.
    /// </para>
    /// </remarks>
    public static string RealPath(string fullPath) => Walk(fullPath).Path;

    /// <summary>The walk with the link lookup and the OS's rule for relative targets supplied, and no magic links.</summary>
    /// <param name="linkTargetOf">The raw target of the link at a path, or null when it is not a link.</param>
    /// <param name="relativeTargetsBySpelling">Windows' rule for a relative link target, rather than POSIX's.</param>
    public static string RealPath(string fullPath, Func<string, string?> linkTargetOf, bool relativeTargetsBySpelling) =>
        Walk(fullPath, linkTargetOf, relativeTargetsBySpelling, isMagicLink: null).Path;

    /// <summary>The real walk on this machine, and whether it crossed a link it could not judge.</summary>
    public static (string Path, bool CrossesMagicLink) Walk(string fullPath) =>
        Walk(fullPath, path => LinkTargetOf(path, fullPath), OperatingSystem.IsWindows(),
            OperatingSystem.IsLinux() ? link => IsOnProcfs(Path.GetDirectoryName(link) ?? link) : null);

    /// <summary>Whether <paramref name="path"/> is on procfs, where every link is judged a magic link.</summary>
    /// <remarks>
    /// Asked of the filesystem rather than of the spelling, so procfs mounted somewhere other than
    /// <c>/proc</c> -- a container given the host's at <c>/host/proc</c> -- is caught too. The ordinary
    /// links there (<c>/proc/self</c>, <c>/proc/mounts</c>) are caught with the magic ones; that costs
    /// nothing, since nothing under procfs is ever an owned directory. A filesystem that cannot be asked
    /// counts as procfs: the answer then is "not owned", which a grant can still override.
    /// </remarks>
    public static bool IsOnProcfs(string path)
    {
        try
        {
            return string.Equals(new DriveInfo(path).DriveFormat, "proc", StringComparison.Ordinal);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return true;
        }
    }

    /// <summary>The walk, with the link lookup, the OS's rule for relative targets and its magic links supplied.</summary>
    /// <param name="isMagicLink">
    /// Whether the link at a path is one the kernel does not follow by name, or null where there are none.
    /// </param>
    /// <returns>
    /// The real path, and whether it crossed a magic link. Past one, the rest is kept as spelled and the
    /// path is not judged: see the server's <c>FileScope.Classify</c>.
    /// </returns>
    public static (string Path, bool CrossesMagicLink) Walk(
        string fullPath, Func<string, string?> linkTargetOf, bool relativeTargetsBySpelling, Func<string, bool>? isMagicLink)
    {
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root))
        {
            return (fullPath, false);
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

            // readlink on /proc/<pid>/root, cwd or fd/N prints a name, but the kernel jumps straight to
            // the object -- a container's root, a descriptor's file -- and an absolute link below it
            // resolves against this process's root again. Neither the name nor anything spliced after it
            // says where the bytes land, so the walk stops judging here.
            if (isMagicLink?.Invoke(next) == true)
            {
                var rest = pending.ToArray();
                return (rest.Length == 0 ? next : Path.Combine([next, .. rest]), true);
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

        return (current, false);
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
}
