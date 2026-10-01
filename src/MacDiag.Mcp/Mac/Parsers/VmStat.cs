using System.Globalization;
using System.Text.RegularExpressions;

namespace MacDiag.Mcp.Mac.Parsers;

/// <param name="PageSize">From the header; null when the header was not found.</param>
/// <param name="AvailableBytes">
/// Free, inactive and speculative pages: memory the system can hand out without paging. Null unless the page
/// size and all three counts were found -- a guess here is a silently wrong number.
/// </param>
/// <param name="Missing">What the output lacked, named as vm_stat prints it.</param>
public sealed record VmStatMemory(long? PageSize, long? AvailableBytes, IReadOnlyList<string> Missing);

/// <summary>vm_stat(1). The page size comes from the header -- 16 KiB on Apple Silicon, 4 KiB on Intel.</summary>
/// <remarks>Never assumed: defaulting to 4096 would undercount an Apple Silicon Mac's memory four times over.</remarks>
public static partial class VmStat
{
    private static readonly string[] AvailableKeys = ["Pages free", "Pages inactive", "Pages speculative"];

    public static VmStatMemory Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var missing = new List<string>();
        var header = PageSizePattern().Match(text);
        long? pageSize = header.Success ? long.Parse(header.Groups[1].Value, CultureInfo.InvariantCulture) : null;
        if (pageSize is null)
        {
            missing.Add("the page size header");
        }

        long pages = 0;
        foreach (var key in AvailableKeys)
        {
            var match = Regex.Match(text, "^" + Regex.Escape(key) + @":\s+(\d+)\.", RegexOptions.Multiline);
            if (match.Success)
            {
                pages += long.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
            }
            else
            {
                missing.Add($"'{key}'");
            }
        }

        return new VmStatMemory(pageSize, missing.Count == 0 ? pages * pageSize : null, missing);
    }

    [GeneratedRegex(@"page size of (\d+) bytes")]
    private static partial Regex PageSizePattern();
}
