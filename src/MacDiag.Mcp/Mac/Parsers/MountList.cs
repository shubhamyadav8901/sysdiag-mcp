using System.Text.RegularExpressions;

namespace MacDiag.Mcp.Mac.Parsers;

public sealed record MacMount(string Device, string MountPoint, string FileSystem, bool ReadOnly, IReadOnlyList<string> Options);

/// <summary>mount(8) with no arguments: "&lt;device&gt; on &lt;mount point&gt; (&lt;type&gt;, &lt;option&gt;, …)".</summary>
/// <remarks>Split on the first " on " and the last " (", so a mount point holding either survives.</remarks>
public static partial class MountList
{
    private static readonly string[] SystemInternal =
        ["/System/Volumes/VM", "/System/Volumes/Preboot", "/System/Volumes/Update", "/System/Volumes/xarts",
         "/System/Volumes/iSCPreboot", "/System/Volumes/Hardware"];

    private static readonly HashSet<string> Disk = new(StringComparer.Ordinal)
        { "apfs", "hfs", "exfat", "msdos", "ntfs", "smbfs", "nfs", "afpfs", "webdav" };

    public static IReadOnlyList<MacMount> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var mounts = new List<MacMount>();
        foreach (var line in text.Split('\n').Select(l => l.TrimEnd('\r')))
        {
            var on = line.IndexOf(" on ", StringComparison.Ordinal);
            var open = line.LastIndexOf(" (", StringComparison.Ordinal);
            if (on <= 0 || open <= on + 4 || !line.EndsWith(')'))
            {
                continue;
            }

            var options = line[(open + 2)..^1].Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            if (options.Length == 0)
            {
                continue;
            }

            mounts.Add(new MacMount(line[..on], line[(on + 4)..open], options[0], options.Contains("read-only"), options[1..]));
        }

        return mounts;
    }

    /// <summary>A volume a person stores things on: a real filesystem, not one of the system's internal APFS volumes.</summary>
    public static bool IsUserVisible(MacMount mount) =>
        Disk.Contains(mount.FileSystem) && !SystemInternal.Contains(mount.MountPoint, StringComparer.Ordinal);

    /// <summary>The user-visible volumes to report free space for: each APFS container once.</summary>
    /// <remarks>
    /// APFS volumes in one container share its free space, so / and /System/Volumes/Data would report the
    /// same number twice. The writable volume stands for its container; the sealed, read-only system volume
    /// is dropped when its container has one.
    /// </remarks>
    public static IReadOnlyList<MacMount> ForSpace(IEnumerable<MacMount> mounts)
    {
        ArgumentNullException.ThrowIfNull(mounts);

        var visible = mounts.Where(IsUserVisible).ToList();
        var chosen = visible
            .Where(m => Container(m) is not null)
            .GroupBy(m => Container(m)!, StringComparer.Ordinal)
            .Select(group => group.FirstOrDefault(m => !m.ReadOnly) ?? group.First())
            .ToHashSet();

        return visible.Where(m => Container(m) is null || chosen.Contains(m)).ToList();
    }

    /// <summary>The APFS container a volume lives in -- /dev/disk3 for /dev/disk3s5 or /dev/disk3s1s1 -- or null.</summary>
    private static string? Container(MacMount mount) =>
        mount.FileSystem == "apfs" && ApfsDevice().Match(mount.Device) is { Success: true } match ? match.Groups[1].Value : null;

    [GeneratedRegex(@"^(/dev/disk\d+)s\d+(s\d+)?$")]
    private static partial Regex ApfsDevice();
}
