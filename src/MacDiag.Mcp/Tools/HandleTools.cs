using System.ComponentModel;
using System.Text;
using MacDiag.Mcp.Diagnostics.Handles;
using ModelContextProtocol.Server;

namespace MacDiag.Mcp.Tools;

/// <summary>Structured result of <c>process_handles</c> and <c>path_handle_search</c>.</summary>
public sealed record PathHandleSearchResult(
    string Summary, string Query, IReadOnlyList<HandleEntry> Handles, bool Elevated, bool Truncated, int TotalMatched,
    IReadOnlyList<string> Limitations);

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
        "List everything one process has open - files, directories, devices, sockets, pipes and kqueues - plus " +
        "the files it has mapped, each with how it was opened: read, write or read-write. Use it to answer what a " +
        "process is actually touching: which log it is writing, which file it holds open, how many sockets it has. " +
        "Scoped to one process, so it is far cheaper than path_handle_search, which walks every process.")]
    public async Task<PathHandleSearchResult> ProcessHandles(
        [Description("Process id. Get a current one from process_list; PIDs are reused.")] int processId,
        [Description("Set false for file references only - open files and directories plus mapped files.")] bool includeAllObjectTypes = true,
        CancellationToken cancellationToken = default) =>
        ToResult(await handles.ForProcessAsync(processId, includeAllObjectTypes, cancellationToken).ConfigureAwait(false));

    internal static PathHandleSearchResult ToResult(HandleSearch search) =>
        new(RenderHandleSummary(search), search.Query, search.Entries, search.Elevated, search.Truncated, search.TotalMatched, search.Limitations);

    internal static string RenderHandleSummary(HandleSearch search)
    {
        var builder = new StringBuilder();
        builder.Append(search.TotalMatched).Append(search.TotalMatched == 1 ? " open object" : " open objects")
            .Append(" for ").AppendLine(RenderLimits.Printable(search.Query));

        foreach (var entry in search.Entries.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(RenderLimits.Printable(entry.ProcessName)).Append(" [").Append(entry.ProcessId).Append("] ")
                .Append(RenderLimits.Printable(entry.HandleValue)).Append(' ').Append(RenderLimits.Printable(entry.Type));
            if (entry.Access is { } access)
            {
                builder.Append(" (").Append(RenderLimits.Printable(access)).Append(')');
            }

            builder.Append(": ").AppendLine(RenderLimits.Printable(entry.Name));
        }

        RenderLimits.NoteElision(builder, search.Entries.Count, "open objects");
        if (search.Truncated)
        {
            builder.Append("Showing the first ").Append(search.Entries.Count).Append(" of ").Append(search.TotalMatched)
                .AppendLine("; narrow the search or raise MACDIAG_MAX_RESULTS.");
        }

        if (!search.Elevated)
        {
            builder.AppendLine("WARNING: the server is not root, so other users' processes were not searched.");
        }

        foreach (var limitation in search.Limitations)
        {
            builder.Append("WARNING: ").AppendLine(RenderLimits.Printable(limitation));
        }

        return builder.ToString().TrimEnd();
    }
}
