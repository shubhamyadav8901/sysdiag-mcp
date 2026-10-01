using System.Xml;
using MacDiag.Mcp.Diagnostics.Services;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Mac.Launchd;

/// <summary>The only place MacDiag runs plutil.</summary>
/// <remarks>
/// <para>Always "-o -": without it, plutil -convert rewrites the file in place, so a read of a system plist would
/// become a write to it. A test keeps every plutil call in this file.</para>
/// <para>No "--" before the path: it is always rooted, so it cannot be read as an option, and plutil's support for
/// "--" is not documented.</para>
/// </remarks>
public static class Plutil
{
    public static async Task<PlistDictionary> ReadAsync(IExternalCommand commands, string plistPath, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(commands);
        ArgumentException.ThrowIfNullOrWhiteSpace(plistPath);

        var result = await commands.RunAsync("plutil", ["-convert", "xml1", "-o", "-", plistPath], timeout, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            throw new ServiceQueryException($"plutil could not read {plistPath}: {result.StandardError.Trim()}");
        }

        try
        {
            return PlistXml.Parse(result.StandardOutput);
        }
        catch (XmlException ex)
        {
            throw new ServiceQueryException($"{plistPath} is not a property list this server can read: {ex.Message}", ex);
        }
    }

    /// <summary>One plist's Label, or null when it has none or cannot be read.</summary>
    public static async Task<string?> LabelAsync(IExternalCommand commands, string plistPath, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var result = await commands.RunAsync("plutil", ["-extract", "Label", "raw", "-o", "-", plistPath], timeout, cancellationToken).ConfigureAwait(false);
        return result.ExitCode == 0 && result.StandardOutput.Trim() is { Length: > 0 } label ? label : null;
    }
}
