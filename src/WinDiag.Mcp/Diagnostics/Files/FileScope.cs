using System.Runtime.Versioning;
using WinDiag.Mcp.Configuration;

namespace WinDiag.Mcp.Diagnostics.Files;

/// <summary>
/// Decides whether a path is inside a directory windiag owns. Shared by both directions of transfer.
/// </summary>
/// <remarks>
/// This is the security boundary for <c>put_file</c> and <c>get_file</c> alike, and it is deliberately
/// one implementation rather than two: a scope check that is copied is a scope check that drifts, and
/// the read side inherits exactly the containment the write side was reviewed for. The path is
/// canonicalised first, so a <c>..</c> that climbs out of an owned directory is judged by where it
/// actually lands, not by how it was spelled.
/// </remarks>
[SupportedOSPlatform("windows")]
internal static class FileScope
{
    /// <summary>The directory the running server executable lives in.</summary>
    public static string ServerDirectory => PathScope.ProcessDirectory;

    /// <summary>Canonicalises a caller-supplied path, or explains why it is unusable.</summary>
    public static string Resolve(string? path, string what) => PathScope.Resolve(path, what);

    /// <summary>Whether the path sits inside a windiag-owned directory or anywhere else.</summary>
    public static WriteScope Of(string fullPath, WinDiagOptions options) =>
        IsUnder(fullPath, ServerDirectory) || IsUnder(fullPath, options.ArtifactDirectory)
            ? WriteScope.WinDiag
            : WriteScope.Arbitrary;

    /// <summary>Names the owned directories, for an error message that says where a path *would* be allowed.</summary>
    public static string Describe(WinDiagOptions options) =>
        $"{ServerDirectory} and {options.ArtifactDirectory}";

    /// <summary>True when <paramref name="candidate"/> is the directory itself or something inside it.</summary>
    /// <remarks>Delegates, so the server and the relay can never disagree about containment.</remarks>
    public static bool IsUnder(string candidate, string directory) => PathScope.IsUnder(candidate, directory);
}
