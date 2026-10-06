
namespace Diag.Mcp.Server.Files;

/// <summary>
/// Decides whether a path is inside a directory the server owns. Shared by both directions of transfer.
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
        string fullPath, FileTransferOptions options, string serverDirectory, bool replacesFinalLink = false) =>
        Classify(fullPath, options, serverDirectory, replacesFinalLink, looseServerMatch: OperatingSystem.IsMacOS());

    /// <param name="looseServerMatch">
    /// Also count a case- or normalisation-variant spelling as inside the server directory, for the self-update
    /// gate only. On case-insensitive APFS the variant is that directory; ownership still compares exactly, so on
    /// a case-sensitive volume a different directory never becomes owned. A variant can add a grant requirement,
    /// never skip one.
    /// </param>
    internal static (WriteScope Scope, bool InServerDirectory) Classify(
        string fullPath, FileTransferOptions options, string serverDirectory, bool replacesFinalLink, bool looseServerMatch)
    {
        var (real, crossesMagicLink) = LandingPath(fullPath, replacesFinalLink);
        if (crossesMagicLink)
        {
            // Unjudgeable, so not owned: it needs the arbitrary grant, as any path outside would.
            // Refusing it outright would also take /proc/<pid>/fd from an operator who granted that.
            return (WriteScope.Arbitrary, false);
        }

        var server = OwnedDirectory(serverDirectory);
        var artifacts = OwnedDirectory(options.ArtifactDirectory);
        var inServer = IsUnder(real, server);
        var gated = inServer || (looseServerMatch && LooseIsUnder(real, server));
        return (inServer || IsUnder(real, artifacts) ? WriteScope.Owned : WriteScope.Arbitrary, gated);
    }

    /// <summary>Whether this runtime really normalises: under invariant globalization Normalize is a silent no-op.</summary>
    private static readonly bool NormalizationWorks =
        ("e" + (char)0x301).Normalize(System.Text.NormalizationForm.FormC).Length == 1;

    /// <summary>Under the directory, ignoring case and Unicode normalisation: APFS's default comparison.</summary>
    internal static bool LooseIsUnder(string candidate, string directory) => LooseIsUnder(candidate, directory, NormalizationWorks);

    /// <remarks>
    /// Without working normalisation a decomposed and a composed spelling cannot be compared, so any path holding
    /// non-ASCII whose leading ASCII agrees with the directory's counts as under it: the gate adds a requirement,
    /// never skips one.
    /// </remarks>
    internal static bool LooseIsUnder(string candidate, string directory, bool normalizationWorks)
    {
        var d = directory.TrimEnd('/');
        if (normalizationWorks)
        {
            // U+017F (long s) folds to 's' in APFS's case folding but not under OrdinalIgnoreCase, and .NET's
            // upper-casing deliberately leaves it alone. It is the one non-ASCII letter that case-folds to ASCII
            // and that NFC does not already map (the Kelvin and Angstrom signs it does), so it is folded here.
            var c = candidate.Normalize(System.Text.NormalizationForm.FormC).Replace('\u017F', 's');
            d = d.Normalize(System.Text.NormalizationForm.FormC).Replace('\u017F', 's');
            return c.Equals(d, StringComparison.OrdinalIgnoreCase) || c.StartsWith(d + "/", StringComparison.OrdinalIgnoreCase);
        }

        static bool Ascii(string s) => s.All(ch => ch <= 0x7F);
        if (Ascii(candidate) && Ascii(d))
        {
            return candidate.Equals(d, StringComparison.OrdinalIgnoreCase) || candidate.StartsWith(d + "/", StringComparison.OrdinalIgnoreCase);
        }

        static string Lead(string s) => new(s.TakeWhile(ch => ch <= 0x7F).ToArray());
        var (leadCandidate, leadDirectory) = (Lead(candidate), Lead(d));
        return leadCandidate.StartsWith(leadDirectory, StringComparison.OrdinalIgnoreCase) ||
               leadDirectory.StartsWith(leadCandidate, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The real path of an owned directory, refused when it cannot be judged.</summary>
    /// <remarks>
    /// Where a request path crossing a magic link is merely unowned, an owned directory crossing one fails
    /// closed. Kept as spelled, it would quietly own nothing -- and for the server directory "not in it"
    /// is the permissive answer, which let an artifact directory inside it skip the self-update gate.
    /// </remarks>
    private static string OwnedDirectory(string directory)
    {
        var (real, crossesMagicLink) = Walk(directory);
        return crossesMagicLink
            ? throw new FileTransferException(
                $"The owned directory '{directory}' cannot be judged: it passes through a link whose target " +
                "is not a path -- a link on procfs, or a Windows mount point named by its volume. " +
                "Configure it by its real path.")
            : real;
    }

    /// <summary>The real path an operation on <paramref name="fullPath"/> touches.</summary>
    /// <remarks>
    /// A read, an append and a Windows write follow a link at the last component, so they touch its
    /// target. A Unix write unlinks the destination and creates a new file in its place, so a link
    /// there is replaced where it sits: only the parent directories are followed, and the name is kept
    /// as spelled. Judging that write at the link's target let <c>/tmp/x -&gt; /var/lib/linuxdiag/x</c>
    /// pass as owned while root created <c>/tmp/x</c>.
    /// </remarks>
    internal static (string Path, bool CrossesMagicLink) LandingPath(string fullPath, bool replacesFinalLink)
    {
        var name = Path.GetFileName(fullPath);
        var parent = Path.GetDirectoryName(fullPath);
        if (replacesFinalLink && !string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(parent))
        {
            var (real, crossesMagicLink) = Walk(parent);
            return (Path.Combine(real, name), crossesMagicLink);
        }

        return Walk(fullPath);
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
    internal static string RealPath(string fullPath) => Walk(fullPath).Path;

    /// <summary>The walk with the link lookup and the OS's rule for relative targets supplied, and no magic links.</summary>
    /// <param name="linkTargetOf">The raw target of the link at a path, or null when it is not a link.</param>
    /// <param name="relativeTargetsBySpelling">Windows' rule for a relative link target, rather than POSIX's.</param>
    internal static string RealPath(string fullPath, Func<string, string?> linkTargetOf, bool relativeTargetsBySpelling) =>
        Walk(fullPath, linkTargetOf, relativeTargetsBySpelling, isMagicLink: null).Path;

    /// <summary>The real walk on this machine, and whether it crossed a link it could not judge.</summary>
    private static (string Path, bool CrossesMagicLink) Walk(string fullPath) =>
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
    internal static bool IsOnProcfs(string path)
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
    /// path is not judged: see <see cref="Classify"/>.
    /// </returns>
    internal static (string Path, bool CrossesMagicLink) Walk(
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
                // Not every unrooted target is relative: .NET strips the NT "\??\" prefix, so a mounted
                // folder's \??\Volume{guid}\ comes back as Volume{guid}\. Spliced under the link, a mount
                // of another volume, or of a shadow copy, inside the artifact directory read as owned.
                // The tag that would say "absolute" is not exposed, so it is stopped like a magic link.
                if (NamesAnNtObject(target))
                {
                    var rest = pending.ToArray();
                    return (rest.Length == 0 ? next : Path.Combine([next, .. rest]), true);
                }

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

    /// <summary>
    /// Whether an unrooted Windows link target is really an absolute NT path with its <c>\??\</c> stripped:
    /// a volume, a device or another namespace, not a name in the link's folder.
    /// </summary>
    /// <remarks>
    /// <para>The names are the ones under <c>\GLOBAL??</c> that reach storage or another namespace:
    /// <c>Volume{guid}</c> (every mounted folder), <c>GLOBALROOT</c> (the whole object namespace, shadow
    /// copies included), <c>Global</c> (an alias of <c>\GLOBAL??</c> itself), <c>HarddiskVolumeN</c>,
    /// <c>HarddiskNPartitionM</c>, <c>PhysicalDriveN</c>, <c>CdRomN</c>, and <c>UNC</c> and <c>Mup</c>
    /// for the network. A colon anywhere means a drive spelled after one of them
    /// (<c>Global\C:\</c>): it is never part of a relative file name.</para>
    /// <para>A real relative symlink to a folder that happens to carry one of these names is caught too.
    /// That costs a grant, not access: the path becomes Arbitrary, never refused outright.</para>
    /// </remarks>
    internal static bool NamesAnNtObject(string target)
    {
        if (target.Contains(':', StringComparison.Ordinal))
        {
            return true;
        }

        var first = target.Split(['\\', '/'], 2)[0];
        return first.Equals("GLOBALROOT", StringComparison.OrdinalIgnoreCase) ||
               first.Equals("Global", StringComparison.OrdinalIgnoreCase) ||
               first.Equals("UNC", StringComparison.OrdinalIgnoreCase) ||
               first.Equals("Mup", StringComparison.OrdinalIgnoreCase) ||
               (first.StartsWith("Volume{", StringComparison.OrdinalIgnoreCase) && first.EndsWith('}')) ||
               first.StartsWith("Harddisk", StringComparison.OrdinalIgnoreCase) ||
               first.StartsWith("PhysicalDrive", StringComparison.OrdinalIgnoreCase) ||
               first.StartsWith("CdRom", StringComparison.OrdinalIgnoreCase);
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
