using System.Globalization;

namespace Diag.Mcp.Server;

/// <summary>How sizes and durations read in every server's summaries, so the two servers agree.</summary>
public static class TextFormat
{
    public static string Uptime(TimeSpan uptime) =>
        uptime.TotalDays >= 1
            ? $"{(int)uptime.TotalDays}d {uptime.Hours}h {uptime.Minutes}m"
            : $"{(int)uptime.TotalHours}h {uptime.Minutes}m";

    public static string Bytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB", "PB"];
        double value = bytes;
        var unit = 0;

        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value.ToString(unit == 0 ? "0" : "0.#", CultureInfo.InvariantCulture)} {units[unit]}";
    }
}
