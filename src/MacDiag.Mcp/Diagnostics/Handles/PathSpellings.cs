namespace MacDiag.Mcp.Diagnostics.Handles;

/// <summary>Every name one path goes by on macOS, so a search written one way finds a file lsof reports another way.</summary>
/// <remarks>
/// <para>Since Catalina the user data lives on its own volume, joined to the sealed system volume by firmlinks: the
/// kernel may report /Users/a/x as /System/Volumes/Data/Users/a/x. And /tmp, /var and /etc are symbolic links into
/// /private, which is the spelling lsof prints -- so the most common search, for something under /tmp or /var/log,
/// would otherwise never match.</para>
/// <para>Applied to each name lsof reports and to the caller's path alike, then compared as substrings.</para>
/// </remarks>
public static class PathSpellings
{
    private const string DataVolume = "/System/Volumes/Data";
    private static readonly string[] PrivateLinks = ["/tmp", "/var", "/etc"];

    /// <summary>Used when /usr/share/firmlinks cannot be read: the list macOS 13 ships.</summary>
    public static readonly IReadOnlyList<string> BuiltInFirmlinks =
        ["/AppleInternal", "/Applications", "/Library", "/System/Library/Caches", "/System/Library/Assets",
         "/System/Library/PreinstalledAssets", "/System/Library/AssetsV2", "/System/Library/PreinstalledAssetsV2",
         "/System/Library/CoreServices/CoreTypes.bundle/Contents/Library", "/System/Library/Speech", "/Users",
         "/Volumes", "/cores", "/opt", "/private", "/usr/local", "/usr/libexec/cups", "/usr/share/snmp"];

    private static readonly Lazy<IReadOnlyList<string>> System = new(() =>
    {
        try
        {
            return File.Exists("/usr/share/firmlinks") && ParseFirmlinks(File.ReadAllText("/usr/share/firmlinks")) is { Count: > 0 } listed
                ? listed
                : BuiltInFirmlinks;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return BuiltInFirmlinks;
        }
    });

    /// <summary>The firmlinked paths this Mac declares, or the built-in list.</summary>
    public static IReadOnlyList<string> SystemFirmlinks => System.Value;

    /// <summary>/usr/share/firmlinks: one "&lt;path&gt;\t&lt;target&gt;" per line.</summary>
    public static IReadOnlyList<string> ParseFirmlinks(string text) =>
        text.Split('\n')
            .Select(line => line.Split('\t')[0].Trim())
            .Where(path => path.StartsWith('/'))
            .ToList();

    public static IReadOnlyList<string> Of(string path, IReadOnlyList<string> firmlinks)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(firmlinks);

        var spellings = new List<string> { path };
        // Each rule can enable another (/tmp → /private/tmp → its Data spelling), so apply them until nothing is new.
        for (var i = 0; i < spellings.Count && spellings.Count < 16; i++)
        {
            foreach (var alternative in Alternatives(spellings[i], firmlinks))
            {
                if (!spellings.Contains(alternative, StringComparer.Ordinal))
                {
                    spellings.Add(alternative);
                }
            }
        }

        return spellings;
    }

    private static IEnumerable<string> Alternatives(string path, IReadOnlyList<string> firmlinks)
    {
        if (Under(path, DataVolume))
        {
            var rest = path[DataVolume.Length..];
            if (firmlinks.Any(f => Under(rest, f)))
            {
                yield return rest;
            }
        }
        else if (firmlinks.Any(f => Under(path, f)))
        {
            yield return DataVolume + path;
        }

        foreach (var link in PrivateLinks)
        {
            if (Under(path, "/private" + link))
            {
                yield return path["/private".Length..];
            }
            else if (Under(path, link))
            {
                yield return "/private" + path;
            }
        }
    }

    private static bool Under(string path, string directory) =>
        path.Equals(directory, StringComparison.Ordinal) || path.StartsWith(directory + "/", StringComparison.Ordinal);
}
