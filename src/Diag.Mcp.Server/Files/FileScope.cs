
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
    /// comparison from either side. On Windows the walk also spells every existing component by its long
    /// name and a drive root by its letter, so an 8.3 short name or a <c>\\?\</c> prefix cannot either:
    /// see <see cref="PathScope.Walk(string, Func{string, string?}, bool, Func{string, bool}?, Func{string, string}?)"/>.</para>
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
        string fullPath, FileTransferOptions options, string serverDirectory, bool replacesFinalLink, bool looseServerMatch) =>
        Classify(fullPath, options, serverDirectory, replacesFinalLink, looseServerMatch, NetworkPath.IsNetworkOrDevice, Walk);

    /// <param name="isNetworkOrDevice">The network-path rule, supplied so a test can run Windows' on any OS.</param>
    /// <param name="walk">The real-path walk, supplied so a test can see what was looked up.</param>
    internal static (WriteScope Scope, bool InServerDirectory) Classify(
        string fullPath, FileTransferOptions options, string serverDirectory, bool replacesFinalLink, bool looseServerMatch,
        Func<string, bool> isNetworkOrDevice, Func<string, (string Path, bool CrossesMagicLink)> walk)
    {
        // A share or a device is never owned, and walking it to find out is itself the SMB connection
        // that hands the machine account's credentials to whoever named the host.
        if (isNetworkOrDevice(fullPath))
        {
            return (WriteScope.Arbitrary, false);
        }

        var (real, crossesMagicLink) = LandingPath(fullPath, replacesFinalLink, walk);
        if (crossesMagicLink)
        {
            // Unjudgeable, so not owned: it needs the arbitrary grant, as any path outside would.
            // Refusing it outright would also take /proc/<pid>/fd from an operator who granted that.
            return (WriteScope.Arbitrary, false);
        }

        var server = OwnedDirectory(serverDirectory, walk);
        var artifacts = OwnedDirectory(options.ArtifactDirectory, walk);
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
    /// "Configure it by its real path" was the old advice, and for a disk mounted only at a folder there
    /// is none: its \\?\Volume{guid}\ spelling is a device path, refused like a share.
    /// </remarks>
    private static string OwnedDirectory(string directory, Func<string, (string Path, bool CrossesMagicLink)> walk)
    {
        var (real, crossesMagicLink) = walk(directory);
        return crossesMagicLink
            ? throw new FileTransferException(
                $"The owned directory '{directory}' cannot be judged: it passes through a link whose target " +
                "cannot be followed by name -- a link on procfs, or on Windows a folder a volume is mounted " +
                "at, a junction to a device, or a relative symbolic link. Move it to a directory reached " +
                "without one: for a disk mounted only at a folder, give the disk a drive letter and use a " +
                "directory on that drive letter.")
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
    internal static (string Path, bool CrossesMagicLink) LandingPath(
        string fullPath, bool replacesFinalLink, Func<string, (string Path, bool CrossesMagicLink)> walk)
    {
        var name = Path.GetFileName(fullPath);
        var parent = Path.GetDirectoryName(fullPath);
        if (replacesFinalLink && !string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(parent))
        {
            var (real, crossesMagicLink) = walk(parent);
            return (Path.Combine(real, name), crossesMagicLink);
        }

        return walk(fullPath);
    }

    /// <summary>How many links one resolution may follow before it is called a loop.</summary>
    internal const int MaxLinkHops = PathScope.MaxLinkHops;

    /// <summary>The path with every link in every existing component resolved: <see cref="PathScope.RealPath(string)"/>.</summary>
    internal static string RealPath(string fullPath) => PathScope.RealPath(fullPath);

    /// <inheritdoc cref="PathScope.RealPath(string, Func{string, string?}, bool)"/>
    internal static string RealPath(string fullPath, Func<string, string?> linkTargetOf, bool windowsTargets) =>
        PathScope.RealPath(fullPath, linkTargetOf, windowsTargets);

    private static (string Path, bool CrossesMagicLink) Walk(string fullPath) => PathScope.Walk(fullPath);

    /// <inheritdoc cref="PathScope.IsOnProcfs(string)"/>
    internal static bool IsOnProcfs(string path) => PathScope.IsOnProcfs(path);

    /// <inheritdoc cref="PathScope.Walk(string, Func{string, string?}, bool, Func{string, bool}?)"/>
    internal static (string Path, bool CrossesMagicLink) Walk(
        string fullPath, Func<string, string?> linkTargetOf, bool windowsTargets, Func<string, bool>? isMagicLink) =>
        PathScope.Walk(fullPath, linkTargetOf, windowsTargets, isMagicLink);

    /// <summary>Names the owned directories, for an error message that says where a path *would* be allowed.</summary>
    public static string Describe(FileTransferOptions options) => Describe(options, ServerDirectory);

    internal static string Describe(FileTransferOptions options, string serverDirectory) =>
        $"{serverDirectory} and {options.ArtifactDirectory}";

    /// <summary>True when <paramref name="candidate"/> is the directory itself or something inside it.</summary>
    /// <remarks>Delegates, so the server and the relay can never disagree about containment.</remarks>
    public static bool IsUnder(string candidate, string directory) => PathScope.IsUnder(candidate, directory);
}
