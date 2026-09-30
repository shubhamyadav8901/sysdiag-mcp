using System.Text.RegularExpressions;
using LinuxDiag.Mcp.Linux.External;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <summary>What a caller may name as a service.</summary>
public static partial class ServiceNames
{
    /// <summary>A service unit from 'cron' or 'cron.service'; every other unit type, and every pattern, refused.</summary>
    /// <remarks>
    /// systemctl expands glob patterns in unit names, so 'ssh*' would reach every matching unit past any list
    /// of names checked here. Other unit types are refused because the tools are about services, and
    /// because starting a target such as poweroff.target takes the machine down.
    /// </remarks>
    public static string Normalise(string? name, string parameterName)
    {
        // Trimmed before the check, so " -H" is refused as an option rather than trimmed into one afterwards.
        var value = ExternalArgument.Check(name?.Trim(), parameterName);
        if (!UnitName().IsMatch(value))
        {
            throw new ArgumentException(
                $"'{value}' is not a unit name: use letters, digits and :-_.@\\ only. Glob patterns are not accepted, " +
                "because systemctl would expand them to every matching unit.", parameterName);
        }

        // As systemctl does: a suffix that is not a unit type is part of the name (php8.3-fpm, snap.lxd.daemon).
        var dot = value.LastIndexOf('.');
        if (dot < 0 || !UnitTypes.Contains(value[(dot + 1)..]))
        {
            return value + ".service";
        }

        var suffix = value[(dot + 1)..];
        return suffix == "service"
            ? value
            : throw new ArgumentException($"'{value}' is a .{suffix} unit; only services are accepted here.", parameterName);
    }

    private static readonly HashSet<string> UnitTypes = new(StringComparer.Ordinal)
    {
        "service", "socket", "target", "device", "mount", "automount", "swap", "timer", "path", "slice", "scope",
    };

    [GeneratedRegex(@"^[A-Za-z0-9:_.@\\-]+$")]
    private static partial Regex UnitName();
}
