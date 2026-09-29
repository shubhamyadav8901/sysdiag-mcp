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
    public const string RootsVariable = "WINDIAG_RELAY_FILE_ROOT";

    /// <summary>
    /// Where the roots come from: the variable if set, otherwise the two directories a deploy and a
    /// capture-retrieval actually use.
    /// </summary>
    /// <remarks>
    /// Defaulting to something workable rather than to nothing is deliberate: an empty default makes
    /// both tools inert until an environment variable is set, and the predictable response to a tool
    /// that does nothing is to widen it to everything. Two narrow, useful roots are a better starting
    /// point than a refusal that invites its own removal.
    /// </remarks>
    public static IReadOnlyList<string> Roots(IDictionary? environment = null)
    {
        var configured = Value(environment ?? Environment.GetEnvironmentVariables(), RootsVariable);

        var roots = string.IsNullOrWhiteSpace(configured)
            ? new[] { DefaultBuildRoot, DefaultArtifactRoot }
            : configured.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var resolved = new List<string>(roots.Length);
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
                    $"[windiag-relay] ignoring unusable {RootsVariable} entry '{root}': {ex.Message}");
            }
        }

        return resolved;
    }

    /// <summary>The build tree the relay was published into -- what a deploy pushes from.</summary>
    /// <remarks>
    /// <para>The relay ships at <c>artifacts/diagrelay/DiagRelay.Mcp.exe</c> while the builds it exists to
    /// send sit beside it at <c>artifacts/win-x64</c>, so the useful root is the directory ABOVE the
    /// one the executable is in. An earlier version combined the executable's own directory with
    /// "artifacts" and produced <c>artifacts/relay/artifacts</c>, which does not exist -- the default
    /// was dead, and pushing a build needed <see cref="RootsVariable"/> set, which is exactly the
    /// inert-by-default state this was supposed to avoid.</para>
    /// <para>Climbing one level is bounded deliberately. A relay unpacked straight into <c>C:\Tools</c>
    /// would otherwise default to <c>C:\Tools</c>, which is defensible, but one dropped at a drive root
    /// would default to the whole drive, which is not. A root parent is refused and the executable's own
    /// directory is used instead -- narrower and useless beats wider and silent.</para>
    /// <para>Resolved against the running executable, which is the published single-file exe in every
    /// real deployment. Under <c>dotnet exec</c> or <c>dotnet run</c> that is dotnet's own install
    /// directory, so this default is meaningless while developing -- set <see cref="RootsVariable"/>
    /// there rather than wondering why a path was refused.</para>
    /// </remarks>
    public static string DefaultBuildRoot
    {
        get
        {
            var directory = PathScope.ProcessDirectory;
            var parent = Directory.GetParent(directory);

            // GetParent returns null only at a root; Parent being null in turn means the parent IS a
            // root, and handing out a whole drive is the one outcome worth refusing.
            return parent is null || parent.Parent is null ? directory : parent.FullName;
        }
    }

    /// <summary>Where captures and dumps land locally -- what a pull writes.</summary>
    /// <remarks>
    /// Per-user on every platform. %TEMP% already is on Windows, and so is $TMPDIR on macOS, but on Linux
    /// the temp directory is /tmp: shared and world-writable. There another user could create
    /// /tmp/windiag first and own it, read every dump pulled into it, and plant files inside push_file's
    /// default scope for the next deploy to send to a target. So off Windows it is the user's own XDG
    /// cache directory instead.
    /// </remarks>
    public static string DefaultArtifactRoot => OperatingSystem.IsWindows()
        ? Path.Combine(Path.GetTempPath(), "windiag")
        : Path.Combine(UserCacheDirectory(), "windiag");

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
