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
    /// The names an environment file -- environment.d/*.conf -- assigns a value, in file order, as systemd's
    /// env-file parser (parse_env_file_internal) reads them. Names are as written; whether systemd accepts one as a
    /// variable name is the caller's check.
    /// </summary>
    /// <remarks>
    /// <para>Not <see cref="Values"/>' unit-file reader: this format has no sections and no line continuations
    /// outside a value. Read as a unit file, one "[x]" line put everything after it in a section and hid it, while
    /// systemd -- which drops a line without '=' -- set every variable below it; and "X" continued onto the next
    /// line, joining a real assignment to a name systemd threw away.</para>
    /// <para>A quoted value may span lines, so a line inside one is not an assignment. An empty value sets nothing
    /// ("invalid syntax, ignoring"). A comment ending in a backslash is followed by an ordinary line, as in systemd
    /// 254 and later; 252 still continued the comment, so on older systems a name may be reported that is not set,
    /// never the reverse. Values are not kept: these files hold tokens as often as paths.</para>
    /// </remarks>
    public static IReadOnlyList<string> EnvironmentFileKeys(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        const string whitespace = " \t\n\r";
        var keys = new List<string>();
        var key = new System.Text.StringBuilder();
        var keyTrailingWhitespace = -1;
        var hasValue = false;
        var state = EnvState.PreKey;

        foreach (var c in text)
        {
            var newline = c is '\n' or '\r';
            switch (state)
            {
                case EnvState.PreKey:
                    if (c is '#' or ';')
                    {
                        state = EnvState.Comment;
                    }
                    else if (!whitespace.Contains(c, StringComparison.Ordinal))
                    {
                        state = EnvState.Key;
                        keyTrailingWhitespace = -1;
                        key.Append(c);
                    }

                    break;

                case EnvState.Key:
                    if (newline)
                    {
                        state = EnvState.PreKey;
                        key.Clear();
                    }
                    else if (c == '=')
                    {
                        state = EnvState.PreValue;
                    }
                    else
                    {
                        if (!whitespace.Contains(c, StringComparison.Ordinal))
                        {
                            keyTrailingWhitespace = -1;
                        }
                        else if (keyTrailingWhitespace < 0)
                        {
                            keyTrailingWhitespace = key.Length;
                        }

                        key.Append(c);
                    }

                    break;

                case EnvState.PreValue:
                    if (newline)
                    {
                        state = EnvState.PreKey;
                        Push();
                    }
                    else if (c == '\'')
                    {
                        state = EnvState.SingleQuoted;
                    }
                    else if (c == '"')
                    {
                        state = EnvState.DoubleQuoted;
                    }
                    else if (c == '\\')
                    {
                        state = EnvState.ValueEscape;
                    }
                    else if (!whitespace.Contains(c, StringComparison.Ordinal))
                    {
                        state = EnvState.Value;
                        hasValue = true;
                    }

                    break;

                case EnvState.Value:
                    if (newline)
                    {
                        state = EnvState.PreKey;
                        Push();
                    }
                    else if (c == '\\')
                    {
                        state = EnvState.ValueEscape;
                    }

                    break;

                case EnvState.ValueEscape:
                    // An escaped newline joins the next line to the value, adding nothing.
                    state = EnvState.Value;
                    hasValue |= !newline;
                    break;

                case EnvState.SingleQuoted:
                    if (c == '\'')
                    {
                        state = EnvState.PreValue;
                    }
                    else
                    {
                        hasValue = true;
                    }

                    break;

                case EnvState.DoubleQuoted:
                    if (c == '"')
                    {
                        state = EnvState.PreValue;
                    }
                    else if (c == '\\')
                    {
                        state = EnvState.DoubleQuotedEscape;
                    }
                    else
                    {
                        hasValue = true;
                    }

                    break;

                case EnvState.DoubleQuotedEscape:
                    state = EnvState.DoubleQuoted;
                    hasValue |= c != '\n';
                    break;

                case EnvState.Comment:
                    if (c == '\\')
                    {
                        state = EnvState.CommentEscape;
                    }
                    else if (newline)
                    {
                        state = EnvState.PreKey;
                    }

                    break;

                case EnvState.CommentEscape:
                    state = newline ? EnvState.PreKey : EnvState.Comment;
                    break;
            }
        }

        if (state is not (EnvState.PreKey or EnvState.Key or EnvState.Comment or EnvState.CommentEscape))
        {
            Push();
        }

        return keys;

        void Push()
        {
            if (hasValue)
            {
                keys.Add(keyTrailingWhitespace < 0 ? key.ToString() : key.ToString(0, keyTrailingWhitespace));
            }

            key.Clear();
            hasValue = false;
        }
    }

    private enum EnvState
    {
        PreKey, Key, PreValue, Value, ValueEscape, SingleQuoted, DoubleQuoted, DoubleQuotedEscape, Comment, CommentEscape,
    }

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
