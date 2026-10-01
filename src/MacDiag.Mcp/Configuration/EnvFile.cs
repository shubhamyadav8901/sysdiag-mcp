using System.Collections;

namespace MacDiag.Mcp.Configuration;

/// <summary>The KEY=VALUE file launchd cannot hand a daemon, read by the server itself.</summary>
/// <remarks>
/// A launchd plist is world-readable, so the token cannot live in its EnvironmentVariables; the plist passes
/// --env-file instead, and this file is root:wheel 0600, checked before it is read (see StartupPermissions).
/// </remarks>
public static class EnvFile
{
    public static IReadOnlyDictionary<string, string> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var equals = line.IndexOf('=', StringComparison.Ordinal);
            if (line.StartsWith('#') || equals <= 0 || line[..equals].Trim().Length == 0)
            {
                continue;
            }

            values[line[..equals].Trim()] = line[(equals + 1)..];
        }

        return values;
    }

    /// <summary>The process environment with the file's values laid over it.</summary>
    public static Hashtable Over(IDictionary environment, IReadOnlyDictionary<string, string> file)
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(file);

        var merged = new Hashtable(environment);
        foreach (var (key, value) in file)
        {
            merged[key] = value;
        }

        return merged;
    }
}
