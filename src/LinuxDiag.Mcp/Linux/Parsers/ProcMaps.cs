using System.Globalization;

namespace LinuxDiag.Mcp.Linux.Parsers;

public sealed record MapsEntry(
    ulong Start, ulong End, string Permissions, uint DeviceMajor, uint DeviceMinor, long Inode, string? Path);

/// <param name="Deleted">The file was deleted or replaced on disk after it was mapped: a stale library after an upgrade.</param>
public sealed record MappedFile(string Path, ulong BaseAddress, long SizeBytes, bool Executable, bool Writable, bool Deleted);

/// <summary><c>/proc/&lt;pid&gt;/maps</c>.</summary>
public static class ProcMaps
{
    /// <summary>Names that look like files but are anonymous memory: nothing on disk that could be stale.</summary>
    private static readonly string[] Anonymous = ["/memfd:", "/SYSV", "/dev/zero"];

    public static IReadOnlyList<MapsEntry> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var entries = new List<MapsEntry>();
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            // address perms offset dev inode [path]: the path is everything after the fifth field,
            // spaces included, so the line cannot simply be split.
            var fields = new string[5];
            var position = 0;
            for (var i = 0; i < fields.Length; i++)
            {
                while (position < line.Length && line[position] == ' ')
                {
                    position++;
                }

                var end = line.IndexOf(' ', position);
                end = end < 0 ? line.Length : end;
                fields[i] = line[position..end];
                position = end;
            }

            var dash = fields[0].IndexOf('-', StringComparison.Ordinal);
            if (dash < 0)
            {
                throw new FormatException($"/proc/<pid>/maps line has no address range: '{line}'.");
            }

            var device = fields[3].Split(':');
            if (device.Length != 2)
            {
                throw new FormatException($"/proc/<pid>/maps line has no MAJ:MIN device: '{line}'.");
            }

            var path = position < line.Length ? line[position..].TrimStart() : string.Empty;
            entries.Add(new MapsEntry(
                ulong.Parse(fields[0].AsSpan(0, dash), NumberStyles.HexNumber, CultureInfo.InvariantCulture),
                ulong.Parse(fields[0].AsSpan(dash + 1), NumberStyles.HexNumber, CultureInfo.InvariantCulture),
                fields[1],
                uint.Parse(device[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture),
                uint.Parse(device[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture),
                long.Parse(fields[4], NumberStyles.None, CultureInfo.InvariantCulture),
                path.Length == 0 ? null : path));
        }

        return entries;
    }

    /// <summary>The distinct files mapped, each at its lowest address, with the total mapped size.</summary>
    public static IReadOnlyList<MappedFile> Files(IReadOnlyList<MapsEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        return entries
            .Where(e => e.Path is { } path && path.StartsWith('/') &&
                        !Anonymous.Any(prefix => path.StartsWith(prefix, StringComparison.Ordinal)))
            .GroupBy(e => e.Path!, StringComparer.Ordinal)
            .Select(group =>
            {
                var deleted = DescriptorTarget.IsDeleted(group.Key);
                return new MappedFile(
                    deleted ? group.Key[..^DescriptorTarget.DeletedSuffix.Length] : group.Key,
                    group.Min(e => e.Start),
                    group.Sum(e => (long)(e.End - e.Start)),
                    group.Any(e => e.Permissions.Contains('x', StringComparison.Ordinal)),
                    group.Any(e => e.Permissions.Contains('w', StringComparison.Ordinal)),
                    deleted);
            })
            .OrderBy(f => f.BaseAddress)
            .ToList();
    }
}
