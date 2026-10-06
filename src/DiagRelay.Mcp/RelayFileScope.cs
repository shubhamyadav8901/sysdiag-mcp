using System.Collections;
using Diag.Mcp.Core;

namespace DiagRelay.Mcp;

/// <summary>
/// Decides which directories on THIS machine the relay may read from and write to.
/// </summary>
/// <remarks>
/// <para><c>push_file</c> and <c>pull_file</c> move bytes between the local disk and a target, which is
/// authority the relay did not previously have: before them it only forwarded calls, and nothing it did
/// could read a local file. One tool call that can send any local path to a lab VM is an exfiltration
/// primitive, so the local side is confined the same way the target side already confines
/// <c>put_file</c> and <c>get_file</c>.</para>
/// <para>The canonicalisation and the under-a-root test are taken from <see cref="FileScope"/> rather
/// than written again, for the reason that file already gives: a scope check that is copied is a scope
/// check that drifts. A <c>..</c> is judged by where it lands, not by how it was spelled. What differs
/// is only WHICH roots apply -- the relay's are local build and artifact directories, not the server's
/// own install directory.</para>
/// </remarks>
internal static class RelayFileScope
{
    /// <summary>Semicolon-separated roots, overriding the defaults entirely when set.</summary>
    public const string RootsVariable = "SYSDIAG_RELAY_FILE_ROOT";

    /// <summary>
    /// Where the roots come from: the variable if set, otherwise <see cref="DefaultRoots"/>.
    /// </summary>
    /// <remarks>
    /// Defaulting to something workable rather than to nothing is deliberate: an empty default makes
    /// both tools inert until an environment variable is set, and the predictable response to a tool
    /// that does nothing is to widen it to everything. Narrow, useful roots are a better starting
    /// point than a refusal that invites its own removal.
    /// </remarks>
    public static IReadOnlyList<string> Roots(IDictionary? environment = null)
    {
        var configured = Value(environment ?? Environment.GetEnvironmentVariables(), RootsVariable);

        var roots = string.IsNullOrWhiteSpace(configured)
            ? DefaultRoots
            : configured.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var resolved = new List<string>(roots.Count);
        foreach (var root in roots)
        {
            try
            {
                var full = Path.GetFullPath(root);
                if (!resolved.Contains(full, PathScope.PathComparer))
                {
                    resolved.Add(full);
                }
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                // A typo in one root must not silently widen or void the others.
                Console.Error.WriteLine(
                    $"[sysdiag-relay] ignoring unusable {RootsVariable} entry '{root}': {ex.Message}");
            }
        }

        return resolved;
    }

    /// <summary>
    /// The build tree the relay was published into -- what a deploy pushes from -- or null when the relay
    /// is not running from one.
    /// </summary>
    /// <remarks>
    /// Resolved against the running executable, which is the published single-file exe in every real
    /// deployment. Under <c>dotnet exec</c> or <c>dotnet run</c> it is dotnet itself, which is not in a
    /// build tree, so while developing this is null and <see cref="RootsVariable"/> is how to push a build.
    /// </remarks>
    public static string? DefaultBuildRoot => BuildRootFor(PathScope.ProcessDirectory, UserProfile);

    /// <summary>
    /// The roots that apply when <see cref="RootsVariable"/> is not set: the per-user artifact folder,
    /// plus the build tree when the relay runs from one.
    /// </summary>
    public static IReadOnlyList<string> DefaultRoots =>
        DefaultBuildRoot is { } build ? [build, DefaultArtifactRoot] : [DefaultArtifactRoot];

    /// <summary>
    /// The <c>artifacts</c> directory when <paramref name="executableDirectory"/> is
    /// <c>artifacts/diagrelay</c> or <c>artifacts/diagrelay-&lt;rid&gt;</c>; otherwise null.
    /// </summary>
    /// <remarks>
    /// <para>The relay is published to <c>artifacts/diagrelay</c> while the builds it exists to send sit
    /// beside it in <c>artifacts/win-x64</c>, so in that layout the useful root is the directory ABOVE the
    /// executable's. An earlier version combined the executable's own directory with "artifacts" and
    /// produced <c>artifacts/relay/artifacts</c>, which does not exist -- the default was dead, and pushing
    /// a build needed <see cref="RootsVariable"/> set.</para>
    /// <para>The climb used to happen wherever the relay was, refusing only a drive root. That made the
    /// parent of an ordinary install folder the boundary: <c>~/bin</c> gave the whole home directory,
    /// <c>~/DiagRelay.Mcp</c> gave every user's, and an unpacked release zip gave <c>~/Downloads</c>. With
    /// $HOME in scope one push_file -- prompted by injected text in any forwarded tool result -- copies
    /// ~/.ssh or the targets file with every bearer token onto a target, over plaintext HTTP. So the climb
    /// now needs the layout it was written for, recognised by name; anywhere else there is no build root,
    /// and the per-user artifact folder is the whole default.</para>
    /// <para>Falling back to the executable's own directory was the obvious alternative and is no better:
    /// a relay dropped straight into the home directory would then hand out the home directory itself.</para>
    /// <para>The names alone are not proof -- a home directory can be called <c>artifacts</c> -- so a tree
    /// that is or contains the user profile is refused as well.</para>
    /// </remarks>
    internal static string? BuildRootFor(string executableDirectory, string userProfile)
    {
        var directory = new DirectoryInfo(Path.TrimEndingDirectorySeparator(Path.GetFullPath(executableDirectory)));
        var artifacts = directory.Parent;

        // Matched case-insensitively everywhere: this only recognises a layout the publish step produced
        // and widens nothing by itself -- the profile check below is what bounds it.
        var isRelayFolder =
            directory.Name.Equals(PublishFolder, StringComparison.OrdinalIgnoreCase) ||
            directory.Name.StartsWith(PublishFolder + "-", StringComparison.OrdinalIgnoreCase);

        if (!isRelayFolder ||
            artifacts?.Parent is null ||
            !artifacts.Name.Equals("artifacts", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (!string.IsNullOrEmpty(userProfile) &&
            PathScope.IsUnder(Path.GetFullPath(userProfile), artifacts.FullName))
        {
            return null;
        }

        return artifacts.FullName;
    }

    /// <summary>What the relay's own publish directory is called, alone or suffixed with a RID.</summary>
    private const string PublishFolder = "diagrelay";

    private static string UserProfile => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    /// <summary>Where captures and dumps land locally -- what a pull writes.</summary>
    /// <remarks>
    /// Per-user on every platform. %TEMP% already is on Windows, and so is $TMPDIR on macOS, but on Linux
    /// the temp directory is /tmp: shared and world-writable. There another user could create
    /// /tmp/sysdiag first and own it, read every dump pulled into it, and plant files inside push_file's
    /// default scope for the next deploy to send to a target. So off Windows it is the user's own XDG
    /// cache directory instead.
    /// </remarks>
    public static string DefaultArtifactRoot => OperatingSystem.IsWindows()
        ? Path.Combine(Path.GetTempPath(), "sysdiag")
        : Path.Combine(UserCacheDirectory(), "sysdiag");

    /// <summary>$XDG_CACHE_HOME if it is set and absolute, otherwise ~/.cache.</summary>
    /// <remarks>The XDG spec says a relative value is invalid and must be ignored.</remarks>
    private static string UserCacheDirectory()
    {
        var xdg = Environment.GetEnvironmentVariable("XDG_CACHE_HOME");
        return !string.IsNullOrEmpty(xdg) && Path.IsPathRooted(xdg)
            ? xdg
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cache");
    }

    /// <summary>
    /// Canonicalises a local path and requires it to sit inside one of the roots.
    /// </summary>
    /// <param name="what">Named in the error, so the caller learns which argument was refused.</param>
    public static string Require(string? path, string what, IReadOnlyList<string> roots)
    {
        string full;
        try
        {
            full = PathScope.Resolve(path, what);
        }
        catch (FileTransferException ex)
        {
            throw new RelayException(ex.Message);
        }

        if (roots.Any(root => PathScope.IsUnder(full, root)))
        {
            return full;
        }

        throw new RelayException(
            $"The {what} '{full}' is outside the directories the relay may touch on this machine " +
            $"({string.Join(", ", roots)}). Set {RootsVariable} to a semicolon-separated list of roots to " +
            "widen it -- deliberately, because this is the boundary that stops one tool call copying an " +
            "arbitrary local file onto a target.");
    }

    /// <summary>
    /// Environment variable names are case-insensitive on Windows and case-sensitive everywhere else.
    /// </summary>
    /// <remarks>
    /// Matters here more than most places: this variable sets the confinement root, and on Linux a
    /// case-insensitive lookup could read a differently-named variable than the one the operator set.
    /// </remarks>
    private static StringComparison VariableNameComparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static string? Value(IDictionary environment, string key)
    {
        foreach (DictionaryEntry entry in environment)
        {
            if (entry.Key is string name && string.Equals(name, key, VariableNameComparison))
            {
                return entry.Value as string;
            }
        }

        return null;
    }
}
