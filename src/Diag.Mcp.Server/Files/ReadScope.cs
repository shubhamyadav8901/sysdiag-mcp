namespace Diag.Mcp.Server.Files;

/// <summary>Which files a tool may read the contents of: get_file's rule, for every tool that reads one.</summary>
/// <remarks>
/// <para>Public so a server's own tools go through it rather than a copy. Windiag's <c>query_activity</c>
/// read whatever path it was handed, as SYSTEM and on a read-only server, while <c>get_file</c> beside it
/// refused the same file: one tool's confinement is no boundary if another reads past it.</para>
/// <para>The scope is judged before anything is opened, so a path outside gets the same refusal whether
/// or not it exists -- "does not exist" for some paths would answer that question for all of them.</para>
/// </remarks>
public static class ReadScope
{
    /// <summary>Canonicalises <paramref name="path"/> and refuses it outside the owned directories unless arbitrary read is on.</summary>
    /// <param name="what">What the path is, for the refusal: "source path", "capture path".</param>
    /// <exception cref="FileTransferException">The path is unusable, or outside and arbitrary read is off.</exception>
    public static (string FullPath, WriteScope Scope) Require(string? path, string what, FileTransferOptions options) =>
        Require(path, what, options, FileScope.ServerDirectory);

    internal static (string FullPath, WriteScope Scope) Require(
        string? path, string what, FileTransferOptions options, string serverDirectory)
    {
        ArgumentNullException.ThrowIfNull(options);

        var full = FileScope.Resolve(path, what);
        var scope = FileScope.Of(full, options, serverDirectory);

        if (scope == WriteScope.Arbitrary && !options.AllowArbitraryRead)
        {
            throw new FileTransferException(
                $"'{full}' is outside the directories this server owns ({FileScope.Describe(options, serverDirectory)}), " +
                $"so reading it needs arbitrary read, which is off. Set {options.ArbitraryReadSetting} to " +
                "allow reading anywhere, or copy the file into one of those directories first. " +
                "(run_command can also read a file out if it is enabled.)");
        }

        return (full, scope);
    }
}
