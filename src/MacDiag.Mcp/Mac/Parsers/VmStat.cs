using System.Globalization;
using System.Text.RegularExpressions;

namespace MacDiag.Mcp.Mac.Parsers;

/// <param name="AvailableBytes">Free, inactive and speculative pages: memory the system can hand out without paging.</param>
public sealed record VmStatMemory(long PageSize, long AvailableBytes);

/// <summary>vm_stat(1). The page size comes from the header -- 16 KiB on Apple Silicon, 4 KiB on Intel.</summary>
public static partial class VmStat
{
    public static VmStatMemory Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var header = PageSizePattern().Match(text);
        var pageSize = header.Success ? long.Parse(header.Groups[1].Value, CultureInfo.InvariantCulture) : 4096;

        long Pages(string key)
        {
            var match = Regex.Match(text, "^" + Regex.Escape(key) + @":\s+(\d+)\.", RegexOptions.Multiline);
            return match.Success ? long.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture) : 0;
        }

        return new VmStatMemory(pageSize, (Pages("Pages free") + Pages("Pages inactive") + Pages("Pages speculative")) * pageSize);
    }

    [GeneratedRegex(@"page size of (\d+) bytes")]
    private static partial Regex PageSizePattern();
}
