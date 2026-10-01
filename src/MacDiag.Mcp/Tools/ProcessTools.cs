using System.ComponentModel;
using System.Globalization;
using System.Text;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Processes;
using ModelContextProtocol.Server;

namespace MacDiag.Mcp.Tools;

/// <param name="WorkingSetBytes">Resident set size: windiag's field name.</param>
public sealed record ProcessInfo(
    int ProcessId, int? ParentProcessId, string Name, DateTimeOffset? StartTime, long WorkingSetBytes, long? UserId,
    string? ExecutablePath, string? CommandLine, string State);

/// <summary>Structured result of <c>process_list</c>.</summary>
public sealed record ProcessListToolResult(
    string Summary, IReadOnlyList<ProcessInfo> Processes, int TotalMatched, bool Truncated, IReadOnlyList<string> Limitations);

[McpServerToolType]
public sealed class ProcessTools(IProcessTable processes, MacDiagOptions options)
{
    [McpServerTool(
        Name = "process_list",
        Title = "Running processes",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "List running processes with their PID, parent PID, start time, resident memory, user, state and full " +
        "command line. The command line is the point: it is what tells one java or python process from another. " +
        "Filter by name or command line, or ask for a single PID. Containers run in a virtual machine on macOS, " +
        "so their processes are not host processes and do not appear here.")]
    public async Task<ProcessListToolResult> ProcessList(
        [Description("Match this text against the process name or its command line")] string? nameFilter = null,
        [Description("Return only this process id")] int? processId = null,
        CancellationToken cancellationToken = default)
    {
        var table = await processes.ReadAsync(cancellationToken).ConfigureAwait(false);
        return Build(table, nameFilter, processId, options.MaxResults);
    }

    internal static ProcessListToolResult Build(ProcessTable table, string? nameFilter, int? processId, int maxResults)
    {
        var matched = table.Processes
            .Where(p => processId is null || p.ProcessId == processId)
            .Where(p => string.IsNullOrWhiteSpace(nameFilter) ||
                        p.Name.Contains(nameFilter, StringComparison.OrdinalIgnoreCase) ||
                        p.CommandLine?.Contains(nameFilter, StringComparison.OrdinalIgnoreCase) == true)
            .OrderBy(p => p.Name, StringComparer.Ordinal).ThenBy(p => p.ProcessId)
            .ToList();

        var rows = matched.Take(maxResults)
            .Select(p => new ProcessInfo(
                p.ProcessId, p.ParentProcessId == 0 ? null : p.ParentProcessId, p.Name, p.StartTime, p.ResidentBytes,
                p.UserId, p.ExecutablePath, p.CommandLine, p.State))
            .ToList();
        var truncated = matched.Count > rows.Count;
        return new ProcessListToolResult(
            RenderProcesses(rows, matched.Count, truncated, table.Limitations, nameFilter, processId),
            rows, matched.Count, truncated, table.Limitations);
    }

    internal static string RenderProcesses(
        IReadOnlyList<ProcessInfo> rows, int totalMatched, bool truncated, IReadOnlyList<string> limitations,
        string? nameFilter, int? processId)
    {
        var builder = new StringBuilder();
        var scope = processId is { } pid ? $"PID {pid}" : string.IsNullOrWhiteSpace(nameFilter) ? "all processes" : $"matching '{RenderLimits.Printable(nameFilter)}'";
        builder.Append(totalMatched).Append(totalMatched == 1 ? " process" : " processes").Append(" (").Append(scope).AppendLine(")");

        foreach (var row in rows.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(RenderLimits.Printable(row.Name)).Append(" [").Append(row.ProcessId).Append(']')
                .Append(" uid ").Append(row.UserId?.ToString(CultureInfo.InvariantCulture) ?? "?")
                .Append(", ").Append(TextFormat.Bytes(row.WorkingSetBytes));
            if (row.CommandLine is { } commandLine)
            {
                builder.Append(": ").Append(RenderLimits.Printable(commandLine));
            }

            builder.AppendLine();
        }

        RenderLimits.NoteElision(builder, rows.Count, "processes");
        if (truncated)
        {
            builder.Append("Showing the first ").Append(rows.Count).Append(" of ").Append(totalMatched)
                .AppendLine("; narrow the filter or raise MACDIAG_MAX_RESULTS.");
        }

        foreach (var limitation in limitations)
        {
            builder.Append("WARNING: ").AppendLine(RenderLimits.Printable(limitation));
        }

        return builder.ToString().TrimEnd();
    }
}
