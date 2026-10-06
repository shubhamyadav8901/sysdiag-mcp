using LinuxDiag.Mcp.Linux.Native;

namespace LinuxDiag.Mcp.Hosting;

/// <summary>Whether a directory, and every directory above it, is controlled by trusted accounts alone.</summary>
/// <remarks>
/// <para>For the directories a root service runs from and runs things out of: the binary's, and the artifact
/// directory, where update_self writes the script root then runs and the log root then writes. Another account
/// that can write the directory can swap the script between its creation and sh reading it; one that can write
/// a directory above it can rename the whole thing away and put its own in its place. Either is root.</para>
/// <para>MacDiag makes the same judgement through BSD stat; this one asks statx directly, which reports the owner
/// and mode on every architecture without parsing a tool's output.</para>
/// </remarks>
public static class TrustedDirectory
{
    private const int GroupOrOtherWrite = 0b000_010_010;
    private const int Sticky = 0b1_000_000_000;

    /// <summary>The accounts trusted to control this process's directories: root, and the account it runs as.</summary>
    internal static IReadOnlyCollection<uint> ThisProcess => new HashSet<uint> { 0, LibC.EffectiveUserId() };

    /// <summary>Everything wrong with the directory through the real file system, one sentence each.</summary>
    internal static IReadOnlyList<string> Problems(string path, IReadOnlyCollection<uint> trusted) =>
        Problems(path, trusted, LibC.Status, LibC.RealPath);

    /// <summary>Everything wrong with where a directory not yet made would be made, through the real file system.</summary>
    internal static IReadOnlyList<string> ProblemsBeforeCreating(string path, IReadOnlyCollection<uint> trusted) =>
        ProblemsBeforeCreating(path, trusted, LibC.Status, LibC.RealPath);

    /// <summary>Everything that lets an account outside <paramref name="trusted"/> write or replace the directory.</summary>
    /// <param name="status">Owner and mode, links followed; null when nothing is there.</param>
    /// <param name="realPath">The path with every link resolved; null when it does not exist.</param>
    internal static IReadOnlyList<string> Problems(
        string path, IReadOnlyCollection<uint> trusted, Func<string, FileStatus?> status, Func<string, string?> realPath)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(trusted);

        var spelled = Spelled(path);
        if (realPath(spelled) is not { } real)
        {
            return [$"{spelled} does not exist."];
        }

        var owner = Owner(trusted);
        var problems = new List<string>();
        if (Examine(status, real) is not { IsDirectory: true } leaf)
        {
            problems.Add($"{real} is not a directory.");
        }
        else
        {
            if (!trusted.Contains(leaf.UserId))
            {
                problems.Add($"{real} is owned by uid {leaf.UserId}, {owner}.");
            }

            if ((leaf.Mode & Sticky) != 0)
            {
                problems.Add($"{real} is a shared sticky directory, such as /tmp.");
            }
            else if ((leaf.Mode & GroupOrOtherWrite) != 0)
            {
                problems.Add($"{real} is writable by its group or by everyone.");
            }
        }

        problems.AddRange(Above(Ancestors(spelled).Concat(Ancestors(real)), trusted, status));
        return problems;
    }

    /// <summary>Everything that would let an account outside <paramref name="trusted"/> replace a directory made here.</summary>
    /// <remarks>
    /// Judged before anything is made, not by making it and checking after: a refusal then would leave a new
    /// directory behind -- and every missing one between -- under the very parent it refused.
    /// </remarks>
    /// <param name="status">Owner and mode, links followed; null when nothing is there.</param>
    /// <param name="realPath">The path with every link resolved; null when it does not exist.</param>
    internal static IReadOnlyList<string> ProblemsBeforeCreating(
        string path, IReadOnlyCollection<uint> trusted, Func<string, FileStatus?> status, Func<string, string?> realPath)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(trusted);

        // The directories still missing are made by root, 0700; what can replace them is the nearest one that
        // exists, and everything above it, as spelled and as resolved -- the same rule as for an existing one.
        var spelled = Spelled(path);
        var existing = Ancestors(spelled).Reverse().FirstOrDefault(a => realPath(a) is not null) ?? "/";
        var real = realPath(existing) ?? existing;
        var problems = Above(Ancestors(existing).Append(existing).Concat(Ancestors(real).Append(real)), trusted, status).ToList();
        if (Examine(status, real) is { IsDirectory: false })
        {
            problems.Insert(0, $"{real} is not a directory, so nothing can be made inside it.");
        }

        return problems;
    }

    /// <summary>The problems of directories something sits in, each once.</summary>
    /// <remarks>A sticky directory such as /tmp lets nobody rename another account's entry, so it may be shared.</remarks>
    private static IEnumerable<string> Above(IEnumerable<string> directories, IReadOnlyCollection<uint> trusted, Func<string, FileStatus?> status)
    {
        // Both as spelled and as resolved: a link on the way is replaced by whoever can write the directory the
        // link sits in.
        var owner = Owner(trusted);
        foreach (var ancestor in directories.Distinct(StringComparer.Ordinal))
        {
            if (Examine(status, ancestor) is not { } above)
            {
                yield return $"{ancestor} could not be examined.";
            }
            else if (!trusted.Contains(above.UserId))
            {
                yield return $"{ancestor} is owned by uid {above.UserId}, {owner}, so that account can replace what is in it.";
            }
            else if ((above.Mode & GroupOrOtherWrite) != 0 && (above.Mode & Sticky) == 0)
            {
                yield return $"{ancestor} is writable by its group or by everyone, so another account can replace what is in it.";
            }
        }
    }

    private static string Spelled(string path) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

    private static string Owner(IReadOnlyCollection<uint> trusted) =>
        trusted.Count == 1 && trusted.Contains(0u) ? "not root" : "neither root nor the account this server runs as";

    private static FileStatus? Examine(Func<string, FileStatus?> status, string path)
    {
        try
        {
            return status(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Every directory above the path, root first.</summary>
    private static IEnumerable<string> Ancestors(string path)
    {
        var above = new List<string>();
        for (var slash = path.LastIndexOf('/'); slash > 0; slash = path.LastIndexOf('/', slash - 1))
        {
            above.Add(path[..slash]);
        }

        if (path != "/")
        {
            above.Add("/");
        }

        above.Reverse();
        return above;
    }
}
