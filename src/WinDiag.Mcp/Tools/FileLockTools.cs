using System.ComponentModel;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.Handles;
using WinDiag.Mcp.Diagnostics.Locks;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>who_locks_path</c>.</summary>
public sealed record WhoLocksPathResult(
    string Summary,
    string Path,
    IReadOnlyList<LockHolder> Holders,
    bool Exhaustive);

/// <summary>Structured result of <c>path_handle_search</c>.</summary>
public sealed record PathHandleSearchResult(
    string Summary,
    string Query,
    IReadOnlyList<HandleEntry> Handles,
    bool Elevated,
    bool Truncated,
    int TotalMatched);

/// <summary>Tools answering "what is holding this open?".</summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class FileLockTools
{
    private readonly ILockInspector _locks;
    private readonly IHandleInspector _handles;
    private readonly IPrivilegeProbe _privileges;

    public FileLockTools(ILockInspector locks, IHandleInspector handles, IPrivilegeProbe privileges)
    {
        _locks = locks;
        _handles = handles;
        _privileges = privileges;
    }

    [McpServerTool(
        Name = "who_locks_path",
        Title = "Who locks this path",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Find which processes are holding a file or folder open, using the Windows Restart Manager. " +
        "Fast, needs no administrator rights, and is the right first call for 'the file is in use' / " +
        "'access denied on save' / 'setup cannot replace this DLL' problems. " +
        "IMPORTANT: coverage is not exhaustive. Restart Manager only reports processes it could " +
        "restart, so it can miss services, kernel-held references and memory-mapped sections. " +
        "If it returns no holders and you still believe the file is locked, call path_handle_search, " +
        "which searches every handle on the machine.")]
    public WhoLocksPathResult WhoLocksPath(
        [Description("Full path to the file or folder, for example C:\\ProgramData\\Vendor\\agent.log")]
        string path,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var fullPath = Path.GetFullPath(path);
        var exists = File.Exists(fullPath) || Directory.Exists(fullPath);

        var result = _locks.WhoLocks(fullPath, cancellationToken);
        var summary = RenderLockSummary(result, fullPath, exists);

        return new WhoLocksPathResult(summary, result.Path, result.Holders, result.Exhaustive);
    }

    [McpServerTool(
        Name = "path_handle_search",
        Title = "Exhaustive handle search",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Search open handles across every process for objects whose name contains the given text. " +
        "Use it as the follow-up when who_locks_path comes back empty, since it finds holders Restart " +
        "Manager cannot see. Requires administrator rights for complete results, and requires " +
        "Sysinternals handle.exe to be installed. " +
        "By default it searches FILE handles only, which is fast. Set includeAllObjectTypes to also " +
        "cover registry keys, sections, mutants and events - necessary for 'who is touching this " +
        "registry key', but far slower, so pair it with a narrow search term.")]
    public async Task<PathHandleSearchResult> PathHandleSearch(
        [Description("Text to match anywhere in the object name, for example a full path, a file name, or a registry key fragment")]
        string nameFragment,
        [Description("Search all named kernel object types, not just files. Needed for registry keys. Much slower - use a narrow search term and expect to raise the timeout.")]
        bool includeAllObjectTypes = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nameFragment);

        var result = await _handles.SearchAsync(nameFragment, includeAllObjectTypes, cancellationToken)
            .ConfigureAwait(false);

        return new PathHandleSearchResult(
            Summary: RenderHandleSummary(result),
            Query: result.Query,
            Handles: result.Entries,
            Elevated: result.Elevated,
            Truncated: result.Truncated,
            TotalMatched: result.TotalMatched);
    }

    /// <summary>
    /// Renders the lock result, refusing to let an empty list read as a definitive "nothing holds it".
    /// </summary>
    /// <remarks>
    /// This wording is the tool's most important output. A bare "no holders found" ends an
    /// investigation; the caveat plus a named next step keeps it going.
    /// </remarks>
    internal static string RenderLockSummary(LockQueryResult result, string fullPath, bool pathExists)
    {
        var builder = new StringBuilder();

        if (result.Holders.Count == 0)
        {
            builder.Append("Restart Manager found no process holding ").Append(fullPath).Append('.');

            if (!pathExists)
            {
                builder.Append(" Note that this path does not currently exist, which is the most likely " +
                               "reason for an empty result.");
            }

            builder.Append(" This is NOT proof that nothing holds it: Restart Manager reports only " +
                           "processes it could restart, and misses many services, kernel-held " +
                           "references and memory-mapped sections. For a definitive answer run " +
                           "path_handle_search on this path.");
            return builder.ToString();
        }

        builder.Append(result.Holders.Count)
            .Append(result.Holders.Count == 1 ? " process holds " : " processes hold ")
            .Append(fullPath)
            .AppendLine(":");

        foreach (var holder in result.Holders)
        {
            builder.Append("- ").Append(holder.ProcessName).Append(" (PID ").Append(holder.ProcessId).Append(')');

            if (holder.ServiceShortName is { } service)
            {
                builder.Append(" [service ").Append(service).Append(']');
            }
            else if (holder.Kind != LockHolderKind.Unknown)
            {
                builder.Append(" [").Append(holder.Kind).Append(']');
            }

            if (holder.FriendlyName is { } friendly && !string.Equals(friendly, holder.ProcessName, StringComparison.OrdinalIgnoreCase))
            {
                builder.Append(" - ").Append(friendly);
            }

            if (!holder.StillRunning)
            {
                builder.Append(" (no longer running; do not act on this PID)");
            }

            builder.AppendLine();
        }

        builder.Append("Restart Manager is not exhaustive, so there may be additional holders it cannot " +
                       "see. Run path_handle_search if this list does not explain the problem.");

        return builder.ToString();
    }

    /// <summary>Renders the handle search result, leading with the elevation caveat when it applies.</summary>
    internal static string RenderHandleSummary(HandleSearchResult result)
    {
        var builder = new StringBuilder();

        if (!result.Elevated)
        {
            builder.AppendLine(
                "WARNING: handle.exe ran WITHOUT administrator rights, so this list is partial. It " +
                "cannot see handles in processes running as other users or as SYSTEM, and an absent " +
                "entry here does not mean the handle does not exist. Restart the server elevated for " +
                "a complete answer.");
        }

        if (result.Entries.Count == 0)
        {
            // Say which universe the search was empty over. "No files matched" and "nothing of any
            // kind matched" lead to different next steps, and reporting the first as the second sends
            // the caller away from a registry key that is sitting right there.
            if (result.ProcessScoped)
            {
                // A PID was named, so there is no search term to widen and no point suggesting one.
                builder.Append(result.IncludedAllObjectTypes
                    ? $"{result.Query} holds no open handles of any object type, which for a live " +
                      "process is unusual enough to suspect it has exited. Check process_list."
                    : $"{result.Query} holds no open FILE handles. It may still hold registry keys, " +
                      "sections or other objects -- call again with includeAllObjectTypes=true.");
            }
            else if (result.IncludedAllObjectTypes)
            {
                builder.Append("No open handles of any object type matched '")
                    .Append(result.Query).Append("'.");
            }
            else
            {
                builder.Append("No open FILE handles matched '").Append(result.Query)
                    .Append("'. This search covered file handles only. If you are looking for a ")
                    .Append("registry key or another kernel object, call again with ")
                    .Append("includeAllObjectTypes=true (slower - keep the search term narrow).");
            }

            return builder.ToString();
        }

        builder.Append(result.TotalMatched)
            .Append(result.TotalMatched == 1 ? " handle matches '" : " handles match '")
            .Append(result.Query)
            .AppendLine("':");

        foreach (var entry in result.Entries.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(entry.ProcessName).Append(" (PID ").Append(entry.ProcessId).Append(") ")
                .Append(entry.Type).Append(": ").Append(entry.Name);

            if (entry.User is { } user)
            {
                builder.Append(" [").Append(user).Append(']');
            }

            builder.AppendLine();
        }

        RenderLimits.NoteElision(builder, result.Entries.Count, "returned handles");

        if (result.Truncated)
        {
            builder.Append("Showing the first ").Append(result.Entries.Count).Append(" of ")
                .Append(result.TotalMatched)
                .Append(" matches. Narrow the search text, or raise WINDIAG_MAX_RESULTS, to see the rest.");
        }

        return builder.ToString();
    }
}
