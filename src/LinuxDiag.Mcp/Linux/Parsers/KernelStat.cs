using System.Globalization;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <summary><c>/proc/stat</c>, for its boot time.</summary>
public static class KernelStat
{
    /// <summary>The <c>btime</c> line: boot, in seconds since the epoch, as the kernel itself counts it.</summary>
    /// <remarks>
    /// Taken from here rather than now minus uptime: that subtraction drifts by the time between the two
    /// reads, and a process start time built on it moves between calls.
    /// </remarks>
    public static DateTimeOffset BootTime(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        foreach (var line in text.Split('\n'))
        {
            if (line.StartsWith("btime ", StringComparison.Ordinal))
            {
                return DateTimeOffset.FromUnixTimeSeconds(
                    long.Parse(line.AsSpan(6).Trim(), NumberStyles.None, CultureInfo.InvariantCulture));
            }
        }

        throw new FormatException("/proc/stat has no btime line.");
    }
}
