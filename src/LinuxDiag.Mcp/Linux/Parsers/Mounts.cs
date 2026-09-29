using System.Text;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <summary>One line of /proc/self/mounts.</summary>
public sealed record MountEntry(string Device, string MountPoint, string FileSystem, bool ReadOnly);

/// <summary>/proc/self/mounts, and which of its entries are disks a person would recognise.</summary>
public static class Mounts
{
    /// <summary>Filesystems with real capacity that are not block devices.</summary>
    private static readonly HashSet<string> NetworkAndPooled =
        new(StringComparer.Ordinal) { "nfs", "nfs4", "cifs", "smb3", "zfs", "btrfs", "fuseblk", "9p", "virtiofs" };

    public static IReadOnlyList<MountEntry> Parse(string text)
    {
        var entries = new List<MountEntry>();
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var fields = line.Split(' ');
            if (fields.Length < 4)
            {
                continue;
            }

            var options = fields[3].Split(',');
            entries.Add(new MountEntry(Unescape(fields[0]), Unescape(fields[1]), fields[2], options.Contains("ro")));
        }

        return entries;
    }

    /// <summary>A block device or a network/pooled filesystem; never proc, tmpfs, overlay or a snap image.</summary>
    /// <remarks>
    /// squashfs is excluded outright rather than listed as full: every snap is one, always 100% used,
    /// and a list of a dozen "full" disks trains the reader to ignore the one warning that matters.
    /// overlay is a container's view of disks already listed.
    /// </remarks>
    public static bool IsDiskLike(MountEntry entry) =>
        entry.FileSystem is not ("squashfs" or "overlay")
        && (entry.Device.StartsWith('/') || NetworkAndPooled.Contains(entry.FileSystem));

    /// <summary>The kernel writes space, tab, newline and backslash as three-digit octal escapes.</summary>
    private static string Unescape(string value)
    {
        if (!value.Contains('\\'))
        {
            return value;
        }

        var builder = new StringBuilder(value.Length);
        for (var i = 0; i < value.Length; i++)
        {
            // Three octal digits must follow; a truncated escape is kept as written.
            if (value[i] == '\\' && i + 3 < value.Length
                && value.AsSpan(i + 1, 3).IndexOfAnyExceptInRange('0', '7') < 0)
            {
                builder.Append((char)Convert.ToInt32(value.Substring(i + 1, 3), 8));
                i += 3;
            }
            else
            {
                builder.Append(value[i]);
            }
        }

        return builder.ToString();
    }
}
