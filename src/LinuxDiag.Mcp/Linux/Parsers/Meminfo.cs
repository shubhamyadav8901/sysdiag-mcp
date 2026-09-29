using System.Globalization;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <summary>/proc/meminfo, in bytes.</summary>
public static class Meminfo
{
    public static (long TotalBytes, long AvailableBytes) Parse(string text)
    {
        var kb = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var line in text.Split('\n'))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            var number = line[(colon + 1)..].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (long.TryParse(number, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
            {
                kb[line[..colon]] = value;
            }
        }

        var total = kb.GetValueOrDefault("MemTotal");

        // MemAvailable exists since 3.14. Before it -- and in some containers still -- the usual estimate
        // is free memory plus the page cache and buffers the kernel can reclaim.
        var available = kb.TryGetValue("MemAvailable", out var reported)
            ? reported
            : kb.GetValueOrDefault("MemFree") + kb.GetValueOrDefault("Buffers") + kb.GetValueOrDefault("Cached");

        return (total * 1024, available * 1024);
    }
}
