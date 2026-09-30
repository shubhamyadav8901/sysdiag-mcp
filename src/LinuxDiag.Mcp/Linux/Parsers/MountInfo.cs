using System.Text;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <summary>One line of mountinfo. Not Mounts.cs's MountEntry, which /proc/mounts feeds and which has no superblock options.</summary>
/// <param name="Options">The mount's own options and its superblock's, merged: either one saying ro makes it read-only.</param>
public sealed record MountInfoEntry(string MountPoint, string FileSystemType, string Source, IReadOnlyList<string> Options)
{
    public bool ReadOnly => Options.Contains("ro");

    public bool NoExec => Options.Contains("noexec");
}

/// <summary><c>/proc/self/mountinfo</c>, which unlike /proc/mounts keeps per-mount and superblock options apart.</summary>
public static class MountInfo
{
    public const string SelfPath = "/proc/self/mountinfo";

    public static IReadOnlyList<MountInfoEntry> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var mounts = new List<MountInfoEntry>();
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var fields = line.Split(' ');
            // Optional fields (shared:N, master:N) sit between field 6 and the "-" separator.
            var separator = fields.Length > 6 ? Array.IndexOf(fields, "-", 6) : -1;
            if (separator < 0 || fields.Length < separator + 4)
            {
                continue;
            }

            var options = fields[5].Split(',').Concat(fields[separator + 3].Split(',')).Distinct(StringComparer.Ordinal).ToList();
            mounts.Add(new MountInfoEntry(Unescape(fields[4]), fields[separator + 1], Unescape(fields[separator + 2]), options));
        }

        return mounts;
    }

    /// <summary>The mount a path is on: the longest covering mount point, the last listed winning a tie, since a later mount hides an earlier one.</summary>
    public static MountInfoEntry? Containing(IReadOnlyList<MountInfoEntry> mounts, string path)
    {
        ArgumentNullException.ThrowIfNull(mounts);

        MountInfoEntry? best = null;
        foreach (var mount in mounts)
        {
            var covers = mount.MountPoint == "/" || path == mount.MountPoint ||
                         path.StartsWith(mount.MountPoint + "/", StringComparison.Ordinal);
            if (covers && (best is null || mount.MountPoint.Length >= best.MountPoint.Length))
            {
                best = mount;
            }
        }

        return best;
    }

    /// <summary>The kernel writes space, tab, newline and backslash in a path as a backslash and three octal digits.</summary>
    internal static string Unescape(string value)
    {
        if (!value.Contains('\\', StringComparison.Ordinal))
        {
            return value;
        }

        var bytes = new List<byte>();
        for (var i = 0; i < value.Length; i++)
        {
            // Three octal digits must follow, so index i + 3 must exist.
            if (value[i] == '\\' && i + 3 < value.Length &&
                value[i + 1] is >= '0' and <= '7' && value[i + 2] is >= '0' and <= '7' && value[i + 3] is >= '0' and <= '7')
            {
                bytes.Add(Convert.ToByte(value.Substring(i + 1, 3), 8));
                i += 3;
            }
            else
            {
                bytes.AddRange(Encoding.UTF8.GetBytes(value[i].ToString()));
            }
        }

        return Encoding.UTF8.GetString(bytes.ToArray());
    }
}
