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
    /// <summary>The program, named once: the capability table refers to it instead of spelling it again.</summary>
    public const string Program = "plutil";

    public static async Task<PlistDictionary> ReadAsync(IExternalCommand commands, string plistPath, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(commands);
        ArgumentException.ThrowIfNullOrWhiteSpace(plistPath);

        var result = await commands.RunAsync(Program, ["-convert", "xml1", "-o", "-", plistPath], timeout, cancellationToken).ConfigureAwait(false);
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
        var result = await commands.RunAsync(Program, ["-extract", "Label", "raw", "-o", "-", plistPath], timeout, cancellationToken).ConfigureAwait(false);
        return result.ExitCode == 0 && result.StandardOutput.Trim() is { Length: > 0 } label ? label : null;
    }

    /// <summary>Several plists' Labels from one plutil run: the i-th entry is the i-th plist's, or null when plutil did
    /// not answer for every plist, one line each.</summary>
    /// <remarks>
    /// <para>One process for many files, because a process per file is what made a label search slow: ~40 ms each from
    /// this server, and ssh.plist is the 421st of ~900 plists, so service_config took 16 s and ran into its 20 s
    /// scan budget. plutil takes "file..." for every command; one run over all ~900 takes under 200 ms.</para>
    /// <para>plutil prints a line per plist that has a Label and only an error on stderr for one that has none, so
    /// after a failure the lines no longer say which file they came from -- and whether it carried on past the
    /// failure is not documented. Then this answers null rather than guess, and the caller asks again in parts.</para>
    /// </remarks>
    public static async Task<string[]?> LabelsAsync(
        IExternalCommand commands, IReadOnlyList<string> plistPaths, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(commands);
        ArgumentNullException.ThrowIfNull(plistPaths);

        var result = await commands.RunAsync(Program, ["-extract", "Label", "raw", "-o", "-", .. plistPaths], timeout, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            return null;
        }

        var lines = result.StandardOutput.Split('\n');
        var count = lines.Length > 0 && lines[^1].Length == 0 ? lines.Length - 1 : lines.Length;

        // A Label holding a newline spans two lines, which would shift every later one onto the wrong file.
        return count == plistPaths.Count ? lines[..count].Select(l => l.Trim()).ToArray() : null;
    }
}
