using System.Collections;
using System.Globalization;

namespace Diag.Mcp.Server;

/// <summary>Strict parsing of a server's environment settings.</summary>
/// <remarks>
/// Strict on purpose: a typo in a boolean fails startup rather than quietly meaning false, because a
/// grant that silently did not apply is found out on a target, much later, as a missing tool. Every
/// helper takes the full variable name, so each server keeps its own spelling of every setting.
/// </remarks>
public static class EnvironmentSettings
{
    public static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    /// <summary>Reads a directory path, rejecting a malformed one at startup rather than mid-capture.</summary>
    /// <remarks>
    /// Deliberately resolved to a full path here. A relative artifact directory would otherwise land
    /// wherever the process happened to be started from, which on a target machine is unpredictable and
    /// makes the returned path useless to the caller.
    /// <para>The default is the caller's to give: the kit has none, because the obvious one on Linux --
    /// the temp directory -- is the shared, world-writable /tmp.</para>
    /// </remarks>
    public static string ReadDirectory(IDictionary environment, string name, string defaultValue)
    {
        var raw = NullIfBlank(Read(environment, name));
        if (raw is null)
        {
            return defaultValue;
        }

        try
        {
            return Path.GetFullPath(raw.Trim());
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ConfigurationException($"{name}='{raw}' is not a usable directory path: {ex.Message}");
        }
    }

    public static string? Read(IDictionary environment, string name) =>
        environment.Contains(name) ? environment[name] as string : null;

    public static bool ReadBoolean(IDictionary environment, string name, bool defaultValue)
    {
        var raw = Read(environment, name);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return defaultValue;
        }

        // Deliberately strict. These flags remove capability or add risk, so a typo like
        // WINDIAG_READ_ONLY=ture must fail loudly rather than silently granting write access.
        return raw.Trim().ToLowerInvariant() switch
        {
            "1" or "true" or "yes" or "on" => true,
            "0" or "false" or "no" or "off" => false,
            _ => throw new ConfigurationException(
                $"{name}='{raw}' is not a boolean. Use one of: 1/true/yes/on or 0/false/no/off.")
        };
    }

    public static int ReadInt32(IDictionary environment, string name, int defaultValue, int min, int max)
    {
        var raw = Read(environment, name);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return defaultValue;
        }

        if (!int.TryParse(raw.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
        {
            throw new ConfigurationException($"{name}='{raw}' is not an integer.");
        }

        if (value < min || value > max)
        {
            throw new ConfigurationException($"{name}={value} is out of range; expected {min}..{max}.");
        }

        return value;
    }
}
