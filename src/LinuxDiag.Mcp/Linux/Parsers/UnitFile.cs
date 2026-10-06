namespace LinuxDiag.Mcp.Linux.Parsers;

/// <summary>Settings read from a unit file and its drop-ins, merged the way systemd merges them.</summary>
/// <remarks>
/// For units no running manager can be asked about -- a user's, whose manager runs only while they are logged in.
/// System units are read through <c>systemctl show</c>, which has already done this merge.
/// </remarks>
public static class UnitFile
{
    /// <summary>
    /// The values a setting ends up with: every assignment in <paramref name="section"/>, the unit file first and
    /// then each drop-in in the order given, with an empty assignment clearing everything before it.
    /// </summary>
    /// <remarks>
    /// The reset is how an override replaces a packaged ExecStart rather than adding a second one, and reading
    /// only the unit file's first ExecStart= reported the packaged program while the override's ran.
    /// </remarks>
    public static IReadOnlyList<string> Values(IEnumerable<string> texts, string section, string key)
    {
        ArgumentNullException.ThrowIfNull(texts);

        var values = new List<string>();
        foreach (var text in texts)
        {
            foreach (var (inSection, name, value) in Assignments(text))
            {
                if (inSection == section && name == key)
                {
                    if (value.Length == 0)
                    {
                        values.Clear();
                    }
                    else
                    {
                        values.Add(value);
                    }
                }
            }
        }

        return values;
    }

    /// <summary>
    /// The names a file assigns in a section -- or, for a null section, before any section header, which is how an
    /// environment.d file assigns them -- each once, in the order first assigned.
    /// </summary>
    public static IReadOnlyList<string> Keys(string text, string? section) =>
        Assignments(text ?? string.Empty).Where(a => a.Section == section).Select(a => a.Key).Distinct(StringComparer.Ordinal).ToList();

    /// <summary>The variable names in a systemd environment list: <c>A=1 "B=two words" 'C=3'</c> gives A, B, C.</summary>
    public static IEnumerable<string> EnvironmentNames(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var word = new System.Text.StringBuilder();
        char? quote = null;
        foreach (var c in value + " ")
        {
            if (quote is null && c is '"' or '\'')
            {
                quote = c;
            }
            else if (c == quote)
            {
                quote = null;
            }
            else if (quote is null && char.IsWhiteSpace(c))
            {
                if (word.ToString().IndexOf('=', StringComparison.Ordinal) is > 0 and var equals)
                {
                    yield return word.ToString()[..equals];
                }

                word.Clear();
            }
            else
            {
                word.Append(c);
            }
        }
    }

    /// <summary>A single-valued setting: the last assignment wins; null when unset or reset.</summary>
    public static string? Last(IEnumerable<string> texts, string section, string key) =>
        Values(texts, section, key).LastOrDefault();

    /// <remarks>
    /// As systemd's config parser reads it: a comment line is skipped even inside a continuation, and a line
    /// continues when it ends in a backslash that is not itself escaped, the backslash becoming a space.
    /// </remarks>
    private static IEnumerable<(string? Section, string Key, string Value)> Assignments(string text)
    {
        string? section = null;
        string? continued = null;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.TrimStart() is [ '#' or ';', ..])
            {
                continue;
            }

            line = continued + line;
            if (EndsInUnescapedBackslash(line))
            {
                continued = line[..^1] + " ";
                continue;
            }

            continued = null;
            line = line.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (line[0] == '[' && line[^1] == ']')
            {
                section = line[1..^1];
                continue;
            }

            var equals = line.IndexOf('=', StringComparison.Ordinal);
            if (equals > 0)
            {
                yield return (section, line[..equals].Trim(), line[(equals + 1)..].Trim());
            }
        }
    }

    private static bool EndsInUnescapedBackslash(string line)
    {
        var escaped = false;
        foreach (var c in line)
        {
            escaped = !escaped && c == '\\';
        }

        return escaped;
    }
}
