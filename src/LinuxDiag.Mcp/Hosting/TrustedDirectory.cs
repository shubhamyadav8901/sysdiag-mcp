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

    /// <summary>Everything that lets an account outside <paramref name="trusted"/> write or replace the directory.</summary>
    /// <param name="status">Owner and mode, links followed; null when nothing is there.</param>
    /// <param name="realPath">The path with every link resolved; null when it does not exist.</param>
    internal static IReadOnlyList<string> Problems(
        string path, IReadOnlyCollection<uint> trusted, Func<string, FileStatus?> status, Func<string, string?> realPath)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(trusted);

        var spelled = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        FileStatus? Examine(string p)
        {
            try
            {
                return status(p);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return null;
            }
        }

        if (realPath(spelled) is not { } real)
        {
            return [$"{spelled} does not exist."];
        }

        var owner = trusted.Count == 1 && trusted.Contains(0u) ? "not root" : "neither root nor the account this server runs as";
        var problems = new List<string>();
        if (Examine(real) is not { IsDirectory: true } leaf)
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

        // Above it, both as spelled and as resolved: a link on the way is replaced by whoever can write the
        // directory the link sits in. A sticky directory such as /tmp lets nobody rename another account's entry.
        foreach (var ancestor in Ancestors(spelled).Concat(Ancestors(real)).Distinct(StringComparer.Ordinal))
        {
            if (Examine(ancestor) is not { } above)
            {
                problems.Add($"{ancestor} could not be examined.");
            }
            else if (!trusted.Contains(above.UserId))
            {
                problems.Add($"{ancestor} is owned by uid {above.UserId}, {owner}, so that account can replace what is in it.");
            }
            else if ((above.Mode & GroupOrOtherWrite) != 0 && (above.Mode & Sticky) == 0)
            {
                problems.Add($"{ancestor} is writable by its group or by everyone, so another account can replace what is in it.");
            }
        }

        return problems;
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
