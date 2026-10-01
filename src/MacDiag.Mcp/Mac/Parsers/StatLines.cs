using System.Globalization;

namespace MacDiag.Mcp.Mac.Parsers;

public enum StatKind
{
    Directory,
    File,
    Link,
    Socket,
    Fifo,
    CharacterDevice,
    BlockDevice,
    Other,
}

/// <param name="Mode">The special and permission digits (%Mp%Lp): 0755, 1777.</param>
/// <param name="Flags">chflags(1) names (uchg, schg, restricted, hidden...); empty when there are none.</param>
/// <param name="Denied">Paths stat was refused (Permission denied): not absent, only out of this server's sight.</param>
public sealed record StatOutcome(IReadOnlyDictionary<string, StatLine> Lines, IReadOnlySet<string> Denied);

public sealed record StatLine(string Path, int Uid, int Gid, int Mode, IReadOnlyList<string> Flags, long Size, long ModifiedEpoch, StatKind Kind);

/// <summary>BSD stat -f with every field the diagnostics need, tab-separated.</summary>
/// <remarks>
/// <para>Tabs, not spaces: %HT ("Regular File") and the name both carry spaces, and a group name from a directory
/// service can too. The tab reaches stat as a real character because the runner uses no shell.</para>
/// <para>A name holding a control character is never asked about. stat would print it raw, and a newline in a name
/// planted in a home directory could then forge a whole line ("0 0644 ... Regular File /Library/x") that a check
/// keyed by name would believe. Without such names, matching lines by %N is safe.</para>
/// <para>%Sf, not ls -lO: the flags come in their own field, so a file named "hidden" is not read as a flag.</para>
/// </remarks>
public static class StatLines
{
    public const string Format = "%u\t%g\t%Mp%Lp\t%Sf\t%z\t%m\t%HT\t%N";

    private const int GroupWrite = 0b000_010_000;
    private const int OtherWrite = 0b000_000_010;

    /// <summary>wheel and admin: admins can become root with sudo, so a directory they can write is no way in.</summary>
    public static readonly IReadOnlySet<int> TrustedGroups = new HashSet<int> { 0, 80 };

    public const int Batch = 256;

    public static IReadOnlyList<string> Arguments(IEnumerable<string> paths) => ["-f", Format, "--", .. paths];

    /// <summary>stat run in batches of <see cref="Batch"/> paths, keyed by path, with the paths it was refused told apart.</summary>
    /// <remarks>
    /// <para>Batches, because thousands of paths in one argv outgrow ARG_MAX and the whole call would fail.</para>
    /// <para>stat says why it skipped a path only on stderr, "stat: &lt;path&gt;: stat: Permission denied"; without
    /// reading it, a path in a home this server may not search would pass for one that does not exist.</para>
    /// </remarks>
    public static async Task<StatOutcome> StatOutcomeAsync(
        IExternalCommand commands, IEnumerable<string> paths, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(commands);
        ArgumentNullException.ThrowIfNull(paths);

        var stats = new Dictionary<string, StatLine>(StringComparer.Ordinal);
        var denied = new HashSet<string>(StringComparer.Ordinal);
        foreach (var batch in paths.Where(p => !HasControlCharacter(p)).Distinct(StringComparer.Ordinal).Chunk(Batch))
        {
            var result = await commands.RunAsync("stat", Arguments(batch), timeout, cancellationToken).ConfigureAwait(false);
            var wanted = batch.ToHashSet(StringComparer.Ordinal);
            foreach (var line in Parse(result.StandardOutput).Where(l => wanted.Contains(l.Path)))
            {
                stats.TryAdd(line.Path, line);
            }

            foreach (var path in result.StandardError.Split('\n').Select(Refused).OfType<string>().Where(wanted.Contains))
            {
                denied.Add(path);
            }
        }

        return new StatOutcome(stats, denied);
    }

    /// <summary>The path in one "stat: &lt;path&gt;: stat: Permission denied" line -- or "Operation not permitted",
    /// which is how privacy protection (TCC) refuses a root daemon without Full Disk Access -- or null.</summary>
    private static string? Refused(string line)
    {
        const string Prefix = "stat: ";
        var trimmed = line.TrimEnd('\r');
        foreach (var suffix in new[] { ": stat: Permission denied", ": stat: Operation not permitted" })
        {
            if (trimmed.StartsWith(Prefix, StringComparison.Ordinal) && trimmed.EndsWith(suffix, StringComparison.Ordinal) &&
                trimmed.Length > Prefix.Length + suffix.Length)
            {
                return trimmed[Prefix.Length..^suffix.Length];
            }
        }

        return null;
    }

    public static bool HasControlCharacter(string path) => path.Any(char.IsControl);

    public static IReadOnlyList<StatLine> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var lines = new List<StatLine>();
        foreach (var raw in text.Split('\n'))
        {
            var fields = raw.TrimEnd('\r').Split('\t', 8);
            if (fields.Length != 8 ||
                !int.TryParse(fields[0], NumberStyles.None, CultureInfo.InvariantCulture, out var uid) ||
                !int.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var gid) ||
                fields[2].Length == 0 || !fields[2].All(c => c is >= '0' and <= '7') ||
                !long.TryParse(fields[4], NumberStyles.None, CultureInfo.InvariantCulture, out var size) ||
                !long.TryParse(fields[5], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var modified) ||
                fields[7].Length == 0)
            {
                continue;
            }

            var flags = fields[3] is "-" or "" ? [] : fields[3].Split(',', StringSplitOptions.RemoveEmptyEntries);
            lines.Add(new StatLine(fields[7], uid, gid, Convert.ToInt32(fields[2], 8), flags, size, modified, Kind(fields[6])));
        }

        return lines;
    }

    /// <summary>Whether an account other than <paramref name="owners"/> could change the entry.</summary>
    /// <remarks>A link's own mode means nothing; what it points at is judged as its own entry.</remarks>
    public static bool WritableByOthers(StatLine line, IReadOnlySet<int> owners, IReadOnlySet<int>? trustedGroups = null)
    {
        ArgumentNullException.ThrowIfNull(line);
        ArgumentNullException.ThrowIfNull(owners);

        if (!owners.Contains(line.Uid))
        {
            return true;
        }

        return line.Kind != StatKind.Link &&
               ((line.Mode & OtherWrite) != 0 || ((line.Mode & GroupWrite) != 0 && !(trustedGroups ?? TrustedGroups).Contains(line.Gid)));
    }

    /// <summary>One stat run for every path, keyed by path; names with a control character and absent paths have no entry.</summary>
    /// <remarks>stat exits 1 when any path is missing but still prints the others, so its output is read either way.</remarks>
    public static async Task<IReadOnlyDictionary<string, StatLine>> StatAsync(
        IExternalCommand commands, IEnumerable<string> paths, TimeSpan timeout, CancellationToken cancellationToken)
    {
        return (await StatOutcomeAsync(commands, paths, timeout, cancellationToken).ConfigureAwait(false)).Lines;
    }

    private static StatKind Kind(string type) => type switch
    {
        "Directory" => StatKind.Directory,
        "Regular File" => StatKind.File,
        "Symbolic Link" => StatKind.Link,
        "Socket" => StatKind.Socket,
        "Fifo File" => StatKind.Fifo,
        "Character Device" => StatKind.CharacterDevice,
        "Block Device" => StatKind.BlockDevice,
        _ => StatKind.Other,
    };
}
