using System.ComponentModel;
using System.Text;
using LinuxDiag.Mcp.Diagnostics.Handles;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

/// <summary>Structured result of <c>process_handles</c> and <c>path_handle_search</c>.</summary>
public sealed record PathHandleSearchResult(
    string Summary, string Query, IReadOnlyList<HandleEntry> Handles, bool Elevated, bool Truncated, int TotalMatched,
    int UnreadableProcesses);

[McpServerToolType]
public sealed class HandleTools(IHandleInspector handles)
{
    [McpServerTool(
        Name = "process_handles",
        Title = "Everything one process has open",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "List everything one process has open - files, directories, devices, sockets, pipes and anonymous inodes " +
        "(eventfd, epoll, inotify) - plus the files it has memory-mapped, each with how it was opened: read, write " +
        "or read-write. Use it to answer what a process is actually touching: which log it is writing, which " +
        "deleted file it is keeping alive, how many sockets it holds. Scoped to one process, so it is far cheaper " +
        "than path_handle_search, which walks every process.")]
    public PathHandleSearchResult ProcessHandles(
        [Description("Process id. Get a current one from process_list; PIDs are reused.")] int processId,
        [Description("Set false for file references only - open files and directories plus memory-mapped files.")] bool includeAllObjectTypes = true,
        CancellationToken cancellationToken = default) =>
        ToResult(handles.ForProcess(processId, includeAllObjectTypes, cancellationToken));

    internal static PathHandleSearchResult ToResult(HandleSearch search) =>
        new(RenderHandleSummary(search), search.Query, search.Entries, search.Elevated, search.Truncated,
            search.TotalMatched, search.UnreadableProcesses);

    internal static string RenderHandleSummary(HandleSearch search)
    {
        var builder = new StringBuilder();
        if (!search.Elevated)
        {
            builder.AppendLine(
                "WARNING: the server is not running as root, so this list is partial: it cannot see the open files of " +
                "processes owned by other users, and an absent entry does not mean nothing holds it. Run the server " +
                "as root for a complete answer.");
        }

        if (search.UnreadableProcesses > 0)
        {
            builder.Append(search.UnreadableProcesses).AppendLine(" processes could not be read and are not searched.");
        }

        if (search.Entries.Count == 0)
        {
            if (search.ProcessScoped)
            {
                builder.Append(search.Query).Append(search.IncludedAllObjectTypes
                    ? " holds no open descriptors at all, which for a live process is unusual enough to suspect it has exited. Check process_list."
                    : " has no open or mapped files. Call again with includeAllObjectTypes=true to see its sockets, pipes and other descriptors.");
            }
            else
            {
                builder.Append("No open or mapped file matched '").Append(search.Query).Append("'.");
                if (!search.IncludedAllObjectTypes)
                {
                    builder.Append(" Call again with includeAllObjectTypes=true to also search sockets, pipes and anonymous inodes.");
                }
            }

            return builder.ToString().TrimEnd();
        }

        builder.Append(search.TotalMatched).Append(search.TotalMatched == 1 ? " handle matches '" : " handles match '")
            .Append(search.Query).AppendLine("':");
        foreach (var entry in search.Entries.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(entry.ProcessName).Append(" (PID ").Append(entry.ProcessId).Append(") ")
                .Append(entry.Type).Append(' ').Append(entry.HandleValue).Append(": ").Append(entry.Name);
            if (entry.Access is not null)
            {
                builder.Append(" [").Append(entry.Access).Append(']');
            }

            if (entry.User is not null)
            {
                builder.Append(" [").Append(entry.User).Append(']');
            }

            if (entry.OtherMountNamespace)
            {
                builder.Append(" (a path in the process's own mount namespace)");
            }

            builder.AppendLine();
        }

        RenderLimits.NoteElision(builder, search.Entries.Count, "returned handles");
        if (search.Truncated)
        {
            builder.Append("Showing the first ").Append(search.Entries.Count).Append(" of ").Append(search.TotalMatched)
                .Append(" matches. Narrow the search, or raise LINUXDIAG_MAX_RESULTS, to see the rest.");
        }

        return builder.ToString().TrimEnd();
    }
}
