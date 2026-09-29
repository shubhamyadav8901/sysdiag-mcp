using System.Globalization;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <summary>/proc/uptime: seconds since boot, then idle seconds.</summary>
public static class Uptime
{
    public static TimeSpan Parse(string text)
    {
        var first = text.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()
                    ?? throw new FormatException("/proc/uptime was empty.");
        return TimeSpan.FromSeconds(double.Parse(first, NumberStyles.Float, CultureInfo.InvariantCulture));
    }
}
