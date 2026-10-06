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
        Problems(path, trusted, LibC.LinkStatus, LibC.ReadLink);

    /// <summary>Everything wrong with where a directory not yet made would be made, through the real file system.</summary>
    internal static IReadOnlyList<string> ProblemsBeforeCreating(string path, IReadOnlyCollection<uint> trusted) =>
        ProblemsBeforeCreating(path, trusted, LibC.LinkStatus, LibC.ReadLink);

    /// <summary>Everything that lets an account outside <paramref name="trusted"/> write or replace the directory.</summary>
    /// <param name="linkStatus">Owner and mode of the entry itself, a link not followed; null when nothing is there.</param>
    /// <param name="readLink">A link's target as written; null when nothing is there.</param>
    internal static IReadOnlyList<string> Problems(
        string path, IReadOnlyCollection<uint> trusted, Func<string, FileStatus?> linkStatus, Func<string, string?> readLink)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(trusted);

        var spelled = Spelled(path);
        var walk = Walk(spelled, linkStatus, readLink);
        if (walk.Failure is { } failure)
        {
            return [failure];
        }

        if (walk.Missing)
        {
            return [$"{spelled} does not exist."];
        }

        var real = walk.Reached;
        var owner = Owner(trusted);
        var problems = new List<string>();
        if (Examine(linkStatus, real) is not { IsDirectory: true } leaf)
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

        problems.AddRange(Above(walk, trusted, linkStatus));
        return problems;
    }

    /// <summary>Everything that would let an account outside <paramref name="trusted"/> replace a directory made here.</summary>
    /// <remarks>
    /// Judged before anything is made, not by making it and checking after: a refusal then would leave a new
    /// directory behind -- and every missing one between -- under the very parent it refused.
    /// </remarks>
    /// <param name="linkStatus">Owner and mode of the entry itself, a link not followed; null when nothing is there.</param>
    /// <param name="readLink">A link's target as written; null when nothing is there.</param>
    internal static IReadOnlyList<string> ProblemsBeforeCreating(
        string path, IReadOnlyCollection<uint> trusted, Func<string, FileStatus?> linkStatus, Func<string, string?> readLink)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(trusted);

        // The directories still missing are made by root, 0700; what can replace them is the nearest one that
        // exists, and every directory and link the way to it passes through -- the same rule as for an existing one.
        var walk = Walk(Spelled(path), linkStatus, readLink);
        if (walk.Failure is { } failure)
        {
            return [failure];
        }

        var problems = Above(walk, trusted, linkStatus).ToList();
        if (Examine(linkStatus, walk.Reached) is { IsDirectory: false })
        {
            problems.Insert(0, $"{walk.Reached} is not a directory, so nothing can be made inside it.");
        }

        return problems;
    }

    /// <summary>The problems of every directory the path passes through, and of every link on the way.</summary>
    /// <remarks>
    /// <para>Whoever can write a directory on the way can replace what is in it, link or not. A sticky directory such
    /// as /tmp lets nobody rename another account's entry, so it may be shared -- but its entries' own owners still
    /// can, so a link in one must be a trusted account's. Judged by the link's own owner, never the target's: a
    /// user's /tmp/diag pointing at root's 0700 /root passed when only where it led was examined, and the user could
    /// then repoint it between the check and root's sh opening the script inside.</para>
    /// <para>A link in a directory only trusted accounts can write cannot be changed by anyone else, whoever owns it.</para>
    /// </remarks>
    private static IEnumerable<string> Above(PathWalk walk, IReadOnlyCollection<uint> trusted, Func<string, FileStatus?> linkStatus)
    {
        var owner = Owner(trusted);
        var directories = new Dictionary<string, FileStatus>(StringComparer.Ordinal);
        foreach (var directory in walk.Directories.Distinct(StringComparer.Ordinal))
        {
            if (Examine(linkStatus, directory) is not { } above)
            {
                yield return $"{directory} could not be examined.";
                continue;
            }

            directories[directory] = above;
            if (!trusted.Contains(above.UserId))
            {
                yield return $"{directory} is owned by uid {above.UserId}, {owner}, so that account can replace what is in it.";
            }
            else if ((above.Mode & GroupOrOtherWrite) != 0 && (above.Mode & Sticky) == 0)
            {
                yield return $"{directory} is writable by its group or by everyone, so another account can replace what is in it.";
            }
        }

        foreach (var (link, uid, parent) in walk.Links)
        {
            if (!trusted.Contains(uid) && directories.TryGetValue(parent, out var holder) && (holder.Mode & Sticky) != 0)
            {
                yield return $"{link} is a link owned by uid {uid}, {owner}, in the shared sticky directory {parent}, so that account can point it elsewhere.";
            }
        }
    }

    /// <summary>The way the kernel takes to a path: every directory it passes through, and every link it follows.</summary>
    /// <param name="Reached">The last thing that exists on the way, links resolved: the path itself unless <see cref="Missing"/>.</param>
    /// <param name="Links">Each link followed, its own owner, and the directory it sits in.</param>
    /// <param name="Failure">Why the way could not be followed: a loop, or an entry that could not be examined.</param>
    private sealed record PathWalk(
        string Reached, bool Missing, List<string> Directories, List<(string Link, uint UserId, string Parent)> Links, string? Failure);

    /// <summary>Resolves a path one component at a time, as the kernel does, recording what decides where it leads.</summary>
    /// <remarks>
    /// Not realpath plus the path's own spelling: those miss a link met halfway -- /opt/x leading to /tmp/y leading
    /// to /root passes through /tmp/y, which is neither -- and say nothing of who owns a link. ".." is taken from
    /// the directory actually reached, which is how the kernel takes it after a link, not from the spelling.
    /// </remarks>
    private static PathWalk Walk(string spelled, Func<string, FileStatus?> linkStatus, Func<string, string?> readLink)
    {
        const int MaxLinks = 40;
        var pending = new Stack<string>(spelled.Split('/').Reverse());
        var current = "/";
        var directories = new List<string> { "/" };
        var links = new List<(string, uint, string)>();
        PathWalk Stop(bool missing, string? failure = null) => new(current, missing, directories, links, failure);

        while (pending.TryPop(out var component))
        {
            if (component is "" or ".")
            {
                continue;
            }

            if (component == "..")
            {
                current = current == "/" ? "/" : current[..Math.Max(1, current.LastIndexOf('/'))];
                continue;
            }

            var next = current == "/" ? "/" + component : current + "/" + component;
            FileStatus? status;
            string? target = null;
            try
            {
                status = linkStatus(next);
                if (status is { IsSymbolicLink: true })
                {
                    target = readLink(next);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return Stop(false, $"{next} could not be examined.");
            }

            if (status is not { } found || (found.IsSymbolicLink && target is null))
            {
                return Stop(true);
            }

            if (found.IsSymbolicLink)
            {
                if (links.Count == MaxLinks)
                {
                    return Stop(false, $"{spelled} leads through more than {MaxLinks} links, a loop.");
                }

                links.Add((next, found.UserId, current));
                if (target!.StartsWith('/'))
                {
                    current = "/";
                }

                foreach (var part in target.Split('/').Reverse())
                {
                    pending.Push(part);
                }

                continue;
            }

            current = next;
            if (pending.Any(p => p is not ("" or ".")))
            {
                // A file with more path after it ends the way: nothing below it exists.
                if (!found.IsDirectory)
                {
                    return Stop(true);
                }

                // Passed through, so whoever can write it can replace what follows.
                directories.Add(current);
            }
        }

        return Stop(false);
    }

    // Made absolute but not normalised: GetFullPath folds "a/link/.." to "a" by spelling, while the kernel -- and
    // the walk -- take ".." from wherever the link led.
    private static string Spelled(string path) =>
        Path.IsPathRooted(path) ? path : Path.Combine(Environment.CurrentDirectory, path);

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
}
