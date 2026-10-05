using System.Diagnostics;

namespace MacDiag.Mcp.Mac.Launchd;

/// <param name="Path">The plist, or null when none was found.</param>
/// <param name="Incomplete">The search stopped at its bound before reading every plist: a null Path is then not "none".</param>
public sealed record PlistSearch(string? Path, bool Incomplete, int Scanned);

/// <summary>Finds the plist that defines a launchd label, loaded or not.</summary>
/// <remarks>
/// The file name is usually the label, but not always: com.openssh.sshd lives in ssh.plist. When &lt;label&gt;.plist is
/// not there, each plist's own Label key is read, bounded in count and time, first match wins -- and a search that
/// hits its bound says so, so "not found" is never a guess. The Labels are read in batches, one plutil per batch:
/// see <see cref="Plutil.LabelsAsync"/> for why a process per plist was not good enough.
/// </remarks>
public sealed class LaunchdPlists
{
    public static readonly string[] DaemonDirectories = ["/Library/LaunchDaemons", "/System/Library/LaunchDaemons"];
    public static readonly string[] AgentDirectories = ["/Library/LaunchAgents", "/System/Library/LaunchAgents"];

    internal int MaxScanned { get; init; } = 2000;

    internal TimeSpan ScanBudget { get; init; } = TimeSpan.FromSeconds(20);

    /// <summary>Plists per plutil run. 128 take ~25 ms; the bound keeps one run's argument list and output modest.</summary>
    internal int BatchSize { get; init; } = 128;

    /// <summary>One plutil run's bound: the 5 s a single plist had, with room for a batch of them.</summary>
    private static readonly TimeSpan BatchTimeout = TimeSpan.FromSeconds(15);

    internal Func<string, bool> FileExists { get; init; } = File.Exists;

    internal Func<string, IEnumerable<string>> ListPlists { get; init; } = static directory =>
        Directory.Exists(directory) ? Directory.EnumerateFiles(directory, "*.plist").Order(StringComparer.Ordinal) : [];

    public static bool IsAgent(string plistPath) =>
        AgentDirectories.Any(d => plistPath.StartsWith(d + "/", StringComparison.Ordinal));

    public async Task<PlistSearch> FindAsync(IExternalCommand commands, string label, IReadOnlyList<string> directories, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(commands);

        foreach (var directory in directories)
        {
            var named = $"{directory}/{label}.plist";
            if (FileExists(named))
            {
                return new PlistSearch(named, false, 0);
            }
        }

        var watch = Stopwatch.StartNew();
        var scanned = 0;
        using var plists = directories.SelectMany(ListPlists).GetEnumerator();
        while (true)
        {
            var batch = new List<string>(BatchSize);
            while (batch.Count < Math.Min(BatchSize, MaxScanned - scanned) && plists.MoveNext())
            {
                batch.Add(plists.Current);
            }

            if (batch.Count == 0)
            {
                return new PlistSearch(null, scanned >= MaxScanned && plists.MoveNext(), scanned);
            }

            if (watch.Elapsed > ScanBudget)
            {
                return new PlistSearch(null, true, scanned);
            }

            scanned += batch.Count;
            if (await FindInAsync(commands, label, batch, cancellationToken).ConfigureAwait(false) is { } found)
            {
                return new PlistSearch(found, false, scanned);
            }
        }
    }

    /// <summary>The first of these plists whose Label is the label, asking plutil once for all of them.</summary>
    /// <remarks>
    /// When plutil cannot say which line is whose (a plist with no Label, or one it cannot read), the batch is halved
    /// and each half asked again, first half first so the first match still wins. One such plist costs about two runs
    /// per halving instead of dropping back to a process per plist; a single plist plutil cannot answer for is not a
    /// match, as it always was.
    /// </remarks>
    private static async Task<string?> FindInAsync(IExternalCommand commands, string label, IReadOnlyList<string> plists, CancellationToken cancellationToken)
    {
        if (await Plutil.LabelsAsync(commands, plists, BatchTimeout, cancellationToken).ConfigureAwait(false) is { } labels)
        {
            var index = Array.IndexOf(labels, label);
            return index >= 0 ? plists[index] : null;
        }

        if (plists.Count == 1)
        {
            return null;
        }

        var half = plists.Count / 2;
        return await FindInAsync(commands, label, plists.Take(half).ToArray(), cancellationToken).ConfigureAwait(false)
            ?? await FindInAsync(commands, label, plists.Skip(half).ToArray(), cancellationToken).ConfigureAwait(false);
    }
}
