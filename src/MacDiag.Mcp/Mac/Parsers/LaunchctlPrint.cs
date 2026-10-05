using System.Globalization;
using System.Text.RegularExpressions;

namespace MacDiag.Mcp.Mac.Parsers;

/// <param name="Missing">Expected keys the output lacked, so a null is never read as "none".</param>
public sealed record LaunchdJobState(
    string? State, int? ProcessId, int? LastExitCode, string? LastExitText, string? LastSignal, int? Runs, string? Path,
    string? Program, IReadOnlyList<string> Missing);

/// <summary>launchctl print: an undocumented format Apple calls unstable, so read leniently and only for runtime state.</summary>
/// <remarks>
/// Only "key = value" lines exactly one tab deep belong to the job. Deeper lines belong to nested blocks --
/// endpoints, environment, arguments -- which carry their own "state =" and "pid =" and must never be read as the
/// job's. A line opening a block ("key = {") is not a value.
/// </remarks>
public static partial class LaunchctlPrint
{
    private static readonly string[] Expected = ["state", "path"];

    public static IReadOnlyDictionary<string, string> TopLevel(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var keys = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length < 2 || line[0] != '\t' || line[1] == '\t')
            {
                continue;
            }

            var equals = line.IndexOf(" = ", StringComparison.Ordinal);
            if (equals <= 1)
            {
                continue;
            }

            var value = line[(equals + 3)..].Trim();
            if (value == "{")
            {
                continue;
            }

            keys.TryAdd(line[1..equals].Trim(), value);
        }

        return keys;
    }

    public static LaunchdJobState State(string text)
    {
        var keys = TopLevel(text);
        var exitText = keys.GetValueOrDefault("last exit code");
        return new LaunchdJobState(
            keys.GetValueOrDefault("state"),
            Number(keys.GetValueOrDefault("pid")),
            exitText is not null && LeadingInteger().Match(exitText) is { Success: true } m ? int.Parse(m.Value, CultureInfo.InvariantCulture) : null,
            exitText,
            keys.GetValueOrDefault("last terminating signal"),
            Number(keys.GetValueOrDefault("runs")),
            keys.GetValueOrDefault("path"),
            keys.GetValueOrDefault("program"),
            Expected.Where(k => !keys.ContainsKey(k)).ToList());
    }

    /// <summary>Whether a failed print means "launchd has no such job" -- the only failure that may be read as "not loaded".</summary>
    /// <remarks>Any other failure is an error: treating it as "not loaded" would answer a stop with "nothing to stop".</remarks>
    public static bool IsNotFound(int exitCode, string standardError) =>
        exitCode == 113 || (standardError ?? string.Empty).Contains("Could not find service", StringComparison.OrdinalIgnoreCase);

    private static int? Number(string? value) =>
        int.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var number) ? number : null;

    [GeneratedRegex(@"^-?\d+")]
    private static partial Regex LeadingInteger();
}

/// <summary>launchctl list: "PID\tStatus\tLabel", "-" for no PID.</summary>
public static class LaunchctlList
{
    public static IReadOnlyList<(int? ProcessId, string Status, string Label)> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var rows = new List<(int?, string, string)>();
        foreach (var line in text.Split('\n').Select(l => l.TrimEnd('\r')))
        {
            var columns = line.Split('\t');
            if (columns.Length != 3 || columns[2] == "Label" || columns[2].Length == 0)
            {
                continue;
            }

            int? pid = columns[0] == "-" ? null
                : int.TryParse(columns[0], NumberStyles.None, CultureInfo.InvariantCulture, out var number) ? number
                : -1;
            if (pid == -1)
            {
                continue;
            }

            rows.Add((pid, columns[1], columns[2]));
        }

        return rows;
    }
}

/// <summary>launchctl print-disabled: the "disabled services" block only, in either spelling macOS has used.</summary>
public static partial class LaunchctlDisabled
{
    public static IReadOnlyDictionary<string, bool> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var disabled = new Dictionary<string, bool>(StringComparer.Ordinal);
        var inBlock = false;
        foreach (var raw in text.Split('\n'))
        {
            // Trimmed both ends: a real Mac indents the whole listing by a tab ("\tdisabled services = {", "\t}"),
            // which the documented form leaves out, and a header matched only at column 0 found no block at all.
            var line = raw.Trim();
            if (!inBlock)
            {
                inBlock = line.StartsWith("disabled services = {", StringComparison.Ordinal);
                continue;
            }

            if (line.StartsWith('}'))
            {
                break;
            }

            if (Entry().Match(line) is { Success: true } match)
            {
                disabled[match.Groups[1].Value] = match.Groups[2].Value is "disabled" or "true";
            }
        }

        return disabled;
    }

    [GeneratedRegex(@"^\s*""([^""]+)""\s*=>\s*(disabled|enabled|true|false)\s*$")]
    private static partial Regex Entry();
}
