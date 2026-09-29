namespace Diag.Mcp.Core;

/// <summary>
/// Canonicalises paths and decides whether one sits inside a directory: the containment half of every
/// file-transfer boundary in this family of tools.
/// </summary>
/// <remarks>
/// One implementation, shared by the Windows server's put_file/get_file and the relay's push_file/
/// pull_file, because a scope check that is copied is a scope check that drifts. The path is
/// canonicalised first, so a <c>..</c> that climbs out of a directory is judged by where it actually
/// lands, not by how it was spelled.
/// </remarks>
public static class PathScope
{
    /// <summary>The directory this process's executable lives in.</summary>
    public static string ProcessDirectory =>
        Path.GetDirectoryName(Environment.ProcessPath) ?? Environment.CurrentDirectory;

    /// <summary>Canonicalises a caller-supplied path, or explains why it is unusable.</summary>
    public static string Resolve(string? path, string what)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new FileTransferException($"No {what} was given.");
        }

        try
        {
            return Path.GetFullPath(path.Trim());
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new FileTransferException($"'{path}' is not a usable file path: {ex.Message}");
        }
    }

    /// <summary>True when <paramref name="candidate"/> is the directory itself or something inside it.</summary>
    /// <remarks>
    /// Compared on the canonical forms with a trailing separator, so <c>C:\WinDiagX\f</c> does not count
    /// as being under <c>C:\WinDiag</c> -- a prefix match without the separator boundary is the classic
    /// way a scope check is escaped.
    /// </remarks>
    public static bool IsUnder(string candidate, string directory)
    {
        string root;
        try
        {
            root = Path.GetFullPath(directory);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }

        var rootWithSep = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                          + Path.DirectorySeparatorChar;

        return candidate.Equals(root, StringComparison.OrdinalIgnoreCase)
               || candidate.StartsWith(rootWithSep, StringComparison.OrdinalIgnoreCase);
    }
}
