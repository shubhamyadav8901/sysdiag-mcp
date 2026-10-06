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

        string full;
        try
        {
            full = Path.GetFullPath(path.Trim());
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new FileTransferException($"'{path}' is not a usable file path: {ex.Message}");
        }

        return OperatingSystem.IsWindows() ? WindowsSpelling(full, path, Path.GetFullPath) : full;
    }

    /// <summary>
    /// A Windows drive path in the one spelling that is both judged and written: drive-letter form, and one
    /// that normalising again leaves as it is.
    /// </summary>
    /// <remarks>
    /// <para>The caller writes or reads the spelling this returns, and the walk judges it, so the two must
    /// name the same entry. <see cref="Path.GetFullPath(string)"/> leaves a <c>\\?\</c> or <c>\??\</c> path
    /// untouched, as Windows does, and such a path reaches entries no ordinary spelling can:
    /// <c>\\?\C:\Diag\art\j.\x</c> goes through the entry literally named <c>j.</c>, which every ordinary
    /// lookup reads as <c>j</c>. Judging the drive-letter form of that path while writing the prefixed one
    /// let a junction named <c>j.</c> carry a write past the self-update gate. So the prefix is dropped, and
    /// a path that then normalises to something else is refused: there is no drive-letter spelling of it to
    /// judge, and no file a caller needs is named that way.</para>
    /// <para>Every drive path must also be a fixed point of normalising. The write normalises it once more,
    /// and a spelling that is not where normalising stops would name one entry to the walk and another to
    /// the write.</para>
    /// <para>A share or a volume GUID is returned as it is, for <see cref="NetworkPath"/> to refuse.</para>
    /// </remarks>
    /// <param name="fullPath">The path after <see cref="Path.GetFullPath(string)"/>.</param>
    /// <param name="requested">The path the caller gave, for the refusal.</param>
    /// <param name="getFullPath">Win32's normalisation, supplied so the rule can be pinned on any OS.</param>
    public static string WindowsSpelling(string fullPath, string requested, Func<string, string> getFullPath)
    {
        var drivePath = fullPath.Length >= 7 && DriveLetterRoot(fullPath[..7]).Length == 3 ? fullPath[4..] : fullPath;
        if (!IsDriveRooted(drivePath))
        {
            return fullPath;
        }

        string again;
        try
        {
            again = getFullPath(drivePath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new FileTransferException($"'{requested}' is not a usable file path: {ex.Message}");
        }

        return string.Equals(again, drivePath, StringComparison.Ordinal)
            ? drivePath
            : throw new FileTransferException(
                $"'{requested}' cannot be judged by its ordinary spelling: Windows reads '{drivePath}' as " +
                $"'{again}'. A name ending in '.' or ' ', or a '.' or '..' folder, behind a \\\\?\\ prefix names " +
                "an entry that spelling does not reach, so it is not accepted. Name the file as Windows spells it.");
    }

    /// <summary>The <c>\\?\</c> form of a drive path, which every Win32 call reads exactly as written.</summary>
    /// <remarks>
    /// The walk asks about each component in this form. An ordinary lookup normalises first:
    /// <c>Directory.Exists(@"C:\Diag\art\j ")</c> trims the trailing space and looks at <c>j</c>, while a
    /// write to <c>C:\Diag\art\j \x</c> goes through <c>j </c>, since Windows trims a space only at the end of
    /// a path. A link target, which the kernel follows without normalising, is read literally too. '/' is
    /// turned into '\' first, as an ordinary lookup would, since the prefix stops that as well. Anything not
    /// on a drive letter is returned as it is.
    /// </remarks>
    public static string LiteralWindowsPath(string path) =>
        IsDriveRooted(path) ? @"\\?\" + path.Replace('/', '\\') : path;

    private static bool IsDriveRooted(string path) =>
        path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] is '\\' or '/';

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
    /// <param name="windowsTargets">
    /// Windows' rule for a link target, as .NET reports it: one without a root, or one on a share or device, stops the walk.
    /// </param>
    public static string RealPath(string fullPath, Func<string, string?> linkTargetOf, bool windowsTargets) =>
        Walk(fullPath, linkTargetOf, windowsTargets, isMagicLink: null).Path;

    /// <summary>The real walk on this machine, and whether it crossed a link it could not judge.</summary>
    public static (string Path, bool CrossesMagicLink) Walk(string fullPath) =>
        Walk(fullPath, path => LinkTargetOf(path, fullPath), OperatingSystem.IsWindows(),
            OperatingSystem.IsLinux() ? link => IsOnProcfs(Path.GetDirectoryName(link) ?? link) : null,
            OperatingSystem.IsWindows() ? path => WindowsLongName.Of(path, fullPath) : null);

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

    /// <summary>The walk, with the link lookup, the OS's rule for link targets and its magic links supplied.</summary>
    /// <param name="isMagicLink">
    /// Whether the link at a path is one the kernel does not follow by name, or null where there are none.
    /// </param>
    /// <returns>
    /// The real path, and whether it crossed a magic link. Past one, the rest is kept as spelled and the
    /// path is not judged: see the server's <c>FileScope.Classify</c>.
    /// </returns>
    public static (string Path, bool CrossesMagicLink) Walk(
        string fullPath, Func<string, string?> linkTargetOf, bool windowsTargets, Func<string, bool>? isMagicLink) =>
        Walk(fullPath, linkTargetOf, windowsTargets, isMagicLink, longNameOf: null);

    /// <summary>The walk, with the lookup of an existing component's one true spelling supplied as well.</summary>
    /// <param name="longNameOf">
    /// The path with its last component spelled as the filesystem stores it, or unchanged when it does not
    /// exist; null where a name has only one spelling. On Windows an NTFS 8.3 short name is a second
    /// spelling: see <see cref="WindowsLongName"/>.
    /// </param>
    /// <remarks>
    /// <para>On Windows the walk also settles the two other second spellings of a local directory. A
    /// device-prefixed drive root (<c>\\?\C:\</c>) is the drive letter's own root, and is put back into
    /// that form; the components after it are still looked up literally (<see cref="LiteralWindowsPath"/>),
    /// so the walk does not normalise what the prefix did not. A stream suffix on a directory component (<c>WinDiag::$INDEX_ALLOCATION</c>) names the
    /// directory itself, so it is refused: no real path needs one, and canonicalising it would mean
    /// trusting a long-name lookup with syntax it was not written for.</para>
    /// <para>Each of these let a path really inside the server's folder be spelled so that it did not
    /// start with the folder's name. The self-update gate compares spellings, and "not in the server
    /// directory" is its permissive answer: with an artifact directory above the server's,
    /// <c>C:\Diag\WINDIA~1\crypt32.dll</c> was owned through the artifact directory and never gated,
    /// and the runtime loads its imports from that folder at the next start.</para>
    /// </remarks>
    public static (string Path, bool CrossesMagicLink) Walk(
        string fullPath, Func<string, string?> linkTargetOf, bool windowsTargets, Func<string, bool>? isMagicLink,
        Func<string, string>? longNameOf)
    {
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root))
        {
            return (fullPath, false);
        }

        var current = windowsTargets ? DriveLetterRoot(root) : root;
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

            // NTFS forbids ':' in a name, so on a component that is not the last it can only be stream
            // syntax, and on a directory that names the directory itself under a second spelling.
            if (windowsTargets && pending.Count > 0 && part.Contains(':', StringComparison.Ordinal))
            {
                throw new FileTransferException(
                    $"'{fullPath}' names a stream of the directory '{part}' as a folder on the way to the file. " +
                    "That is the directory itself under another spelling, which is not accepted: name the " +
                    "directory without the ':' suffix.");
            }

            var next = Path.Combine(current, part);
            var target = linkTargetOf(next);
            if (target is null)
            {
                current = longNameOf is null ? next : LongName(current, part, next, longNameOf);
                continue;
            }

            // readlink on /proc/<pid>/root, cwd or fd/N prints a name, but the kernel jumps straight to
            // the object -- a container's root, a descriptor's file -- and an absolute link below it
            // resolves against this process's root again. Neither the name nor anything spliced after it
            // says where the bytes land, so the walk stops judging here.
            if (isMagicLink?.Invoke(next) == true)
            {
                return Unjudged(next, pending);
            }

            if (++hops > MaxLinkHops)
            {
                throw new FileTransferException(
                    $"'{fullPath}' could not be resolved: it passes through more than {MaxLinkHops} links, " +
                    "which is a link loop.");
            }

            // On Windows the target's text cannot be trusted to say whether it is relative. .NET 9 cuts the
            // first four characters off every junction and absolute symlink target, assuming them to be
            // "\??\", and nothing checks: \??\Volume{guid}\ (a mounted folder) comes back as Volume{guid}\,
            // and a junction any user can point at \Device\HarddiskVolume3\ comes back as
            // "ice\HarddiskVolume3\". Spliced under the link's folder, either read as owned while the bytes
            // came from another volume or a shadow copy. Recognising the names was tried, and missed the
            // \Device\ spelling. Only the reparse tag tells relative from absolute, and .NET does not expose
            // it, so an unrooted target is never followed: the path is unjudged, as past a procfs magic
            // link. A real relative symlink -- which needs a privilege to create -- costs the arbitrary grant.
            // A share is stopped too: walking on would be the SMB connection NetworkPath exists to prevent.
            if (windowsTargets &&
                (!Path.IsPathRooted(target) || NetworkPath.IsNetworkOrDevice(target, windows: true, NetworkPath.DriveTypeOf)))
            {
                return Unjudged(next, pending);
            }

            // An absolute target starts again from its own root; a relative one carries on from the
            // directory holding the link, which is where the walk already is.
            var targetRoot = Path.GetPathRoot(target);
            if (!string.IsNullOrEmpty(targetRoot))
            {
                current = Path.GetPathRoot(Path.GetFullPath(targetRoot, current))!;
                current = windowsTargets ? DriveLetterRoot(current) : current;
            }

            PushComponents(pending, target[(targetRoot?.Length ?? 0)..]);
        }

        return (current, false);

        // Past a link the walk cannot follow, the rest is kept as spelled and marked unjudged.
        static (string, bool) Unjudged(string link, Stack<string> rest) =>
            (rest.Count == 0 ? link : Path.Combine([link, .. rest.ToArray()]), true);
    }

    /// <summary>The long spelling of <paramref name="next"/>, with a stream suffix on the last component kept as given.</summary>
    /// <remarks>
    /// A stream can only be on the last component by now -- one further up is refused -- and
    /// <c>a.exe:Zone.Identifier</c> is a real thing to read. The lookup cannot take the ':', so the file's
    /// own name is looked up and the stream put back after it. A bare <c>:stream</c> is a stream of the
    /// directory already resolved, kept as spelled.
    /// </remarks>
    private static string LongName(string current, string part, string next, Func<string, string> longNameOf)
    {
        var stream = part.IndexOf(':', StringComparison.Ordinal);
        return stream switch
        {
            < 0 => longNameOf(next),
            0 => next,
            _ => longNameOf(Path.Combine(current, part[..stream])) + part[stream..]
        };
    }

    /// <summary>A drive's root in its drive-letter form: <c>\\?\C:\</c> and <c>\\.\C:\</c> become <c>C:\</c>.</summary>
    /// <remarks>
    /// The long-path prefix reaches the same directory as the drive letter, and <see cref="NetworkPath"/>
    /// admits it for that reason. The owned directories are configured, and compared, in drive-letter
    /// form, so a path judged in the prefixed form started with neither of them. Any other root -- a
    /// share, a volume GUID -- is returned as it is: those are refused before the walk.
    /// </remarks>
    public static string DriveLetterRoot(string root)
    {
        static bool Separator(char c) => c is '\\' or '/';

        var prefixed = root.Length == 7
                       && ((Separator(root[0]) && Separator(root[1]) && root[2] is '?' or '.') ||
                           (root[0] == '\\' && root[1] == '?' && root[2] == '?'))
                       && Separator(root[3]) && char.IsAsciiLetter(root[4]) && root[5] == ':' && Separator(root[6]);

        return prefixed ? root[4..] : root;
    }

    /// <summary>The raw target of the link at <paramref name="path"/>, or null when it is not a link or does not exist.</summary>
    private static string? LinkTargetOf(string path, string fullPath)
    {
        // Asked literally on Windows, so a name ending in '.' or ' ' is the entry the write goes through.
        path = OperatingSystem.IsWindows() ? LiteralWindowsPath(path) : path;
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
