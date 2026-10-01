using System.Diagnostics;

namespace MacDiag.Mcp.Mac.Launchd;

/// <param name="Path">The plist, or null when none was found.</param>
/// <param name="Incomplete">The search stopped at its bound before reading every plist: a null Path is then not "none".</param>
public sealed record PlistSearch(string? Path, bool Incomplete, int Scanned);

/// <summary>Finds the plist that defines a launchd label, loaded or not.</summary>
/// <remarks>
/// The file name is usually the label, but not always: com.openssh.sshd lives in ssh.plist. When &lt;label&gt;.plist is
/// not there, each plist's own Label key is read, bounded in count and time, first match wins -- and a search that
/// hits its bound says so, so "not found" is never a guess.
/// </remarks>
public sealed class LaunchdPlists
{
    public static readonly string[] DaemonDirectories = ["/Library/LaunchDaemons", "/System/Library/LaunchDaemons"];
    public static readonly string[] AgentDirectories = ["/Library/LaunchAgents", "/System/Library/LaunchAgents"];

    internal int MaxScanned { get; init; } = 2000;

    internal TimeSpan ScanBudget { get; init; } = TimeSpan.FromSeconds(20);

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
        foreach (var plist in directories.SelectMany(ListPlists))
        {
            if (scanned >= MaxScanned || watch.Elapsed > ScanBudget)
            {
                return new PlistSearch(null, true, scanned);
            }

            scanned++;
            if (await Plutil.LabelAsync(commands, plist, TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false) == label)
            {
                return new PlistSearch(plist, false, scanned);
            }
        }

        return new PlistSearch(null, false, scanned);
    }
}
