namespace LinuxDiag.Mcp.Linux.Parsers;

/// <summary>/etc/os-release: what this distribution calls itself.</summary>
public static class OsRelease
{
    public static string PrettyName(string text)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in text.Split('\n'))
        {
            var equals = line.IndexOf('=');
            if (equals > 0)
            {
                values[line[..equals].Trim()] = line[(equals + 1)..].Trim().Trim('"', '\'');
            }
        }

        if (values.TryGetValue("PRETTY_NAME", out var pretty) && pretty.Length > 0)
        {
            return pretty;
        }

        var name = values.GetValueOrDefault("NAME");
        var version = values.GetValueOrDefault("VERSION") ?? values.GetValueOrDefault("VERSION_ID");
        return name is null ? "Linux" : version is null ? name : $"{name} {version}";
    }
}
