using System.ComponentModel;
using System.Text;
using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Diagnostics.Containers;
using LinuxDiag.Mcp.Diagnostics.Processes;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

/// <param name="WorkingSetBytes">Resident set size: windiag's field name, Linux's RSS.</param>
/// <param name="CgroupPath">Always present, so a container no runtime claims is still visible by its raw cgroup.</param>
public sealed record ProcessInfo(
    int ProcessId, int? ParentProcessId, string Name, DateTimeOffset? StartTime, long WorkingSetBytes,
    int ThreadCount, long? UserId, string? ExecutablePath, string? CommandLine, string State, string CgroupPath,
    ProcessContainer? Container, string? NetworkNamespace);

/// <summary>Structured result of <c>process_list</c>.</summary>
public sealed record ProcessListToolResult(
    string Summary, IReadOnlyList<ProcessInfo> Processes, int TotalMatched, bool Truncated,
    int CommandLinesRedacted, string? Limitation);

[McpServerToolType]
public sealed class ProcessTools(IProcessTable processes, IContainerInspector containers, LinuxDiagOptions options)
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
        "List running processes with their PID, parent PID, start time, resident memory, thread count, user, state " +
        "and full command line - and, for a process in a container, the container's runtime, id, name and image " +
        "and the process's PID inside it. The command line is the point: it is what tells one java or python " +
        "process from another. Filter by name, command line or container name, or ask for a single PID. Kernel " +
        "threads are listed without a command line.")]
    public async Task<ProcessListToolResult> ProcessList(
        [Description("Match this text against the process name, its command line or its container's name")] string? nameFilter = null,
        [Description("Return only this process id")] int? processId = null,
        CancellationToken cancellationToken = default)
    {
        var table = processes.Read(cancellationToken);
        var catalog = await containers.ListAsync(table, cancellationToken).ConfigureAwait(false);
        return Build(table, catalog, nameFilter, processId, options.MaxResults);
    }

    internal static ProcessListToolResult Build(
        ProcessTable table, ContainerCatalog catalog, string? nameFilter, int? processId, int maxResults)
    {
        var byId = ContainerJoin.ById(catalog);
        var matched = table.Processes
            .Select(p => (Record: p, Container: ContainerJoin.For(p, byId)))
            .Where(p => processId is null || p.Record.ProcessId == processId)
            .Where(p => string.IsNullOrWhiteSpace(nameFilter) ||
                        p.Record.Name.Contains(nameFilter, StringComparison.OrdinalIgnoreCase) ||
                        p.Record.CommandLine?.Contains(nameFilter, StringComparison.OrdinalIgnoreCase) == true ||
                        p.Container?.Name?.Contains(nameFilter, StringComparison.OrdinalIgnoreCase) == true)
            .OrderBy(p => p.Record.Name, StringComparer.Ordinal)
            .ThenBy(p => p.Record.ProcessId)
            .ToList();

        var rows = matched.Take(maxResults).Select(p => new ProcessInfo(
            p.Record.ProcessId,
            p.Record.ParentProcessId == 0 ? null : p.Record.ParentProcessId,
            p.Record.Name, p.Record.StartTime, p.Record.ResidentBytes, p.Record.ThreadCount, p.Record.UserId,
            p.Record.ExecutablePath, p.Record.CommandLine, p.Record.State, p.Record.CgroupPath, p.Container,
            p.Record.NetworkNamespace)).ToList();

        var limitations = new List<string>(catalog.Limitations);
        if (table.Unreadable > 0)
        {
            limitations.Add($"{table.Unreadable} processes could not be read at all and are not listed; run the server as root.");
        }

        if (table.PartlyUnreadable > 0)
        {
            limitations.Add($"{table.PartlyUnreadable} processes owned by other users could not be fully read: their " +
                            "executable path and namespaces are null. Run the server as root.");
        }

        var limitation = limitations.Count == 0 ? null : string.Join(" ", limitations);
        var redacted = matched.Count(p => p.Record.CommandLineDenied);
        var truncated = matched.Count > maxResults;

        return new ProcessListToolResult(
            RenderProcesses(rows, matched.Count, truncated, redacted, limitation, nameFilter, processId),
            rows, matched.Count, truncated, redacted, limitation);
    }

    internal static string RenderProcesses(
        IReadOnlyList<ProcessInfo> rows, int totalMatched, bool truncated, int redacted, string? limitation,
        string? nameFilter, int? processId)
    {
        var builder = new StringBuilder();
        if (limitation is not null)
        {
            builder.Append("WARNING: ").AppendLine(RenderLimits.Printable(limitation));
        }

        if (rows.Count == 0)
        {
            builder.Append("No process matched");
            if (processId is not null)
            {
                builder.Append(" PID ").Append(processId);
            }

            if (!string.IsNullOrWhiteSpace(nameFilter))
            {
                builder.Append(" '").Append(RenderLimits.Printable(nameFilter)).Append('\'');
            }

            return builder.Append('.').ToString();
        }

        builder.Append(totalMatched).Append(totalMatched == 1 ? " process" : " processes").AppendLine(":");
        foreach (var process in rows.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(RenderLimits.Printable(process.Name)).Append(" (PID ").Append(process.ProcessId);
            if (process.ParentProcessId is { } parent)
            {
                builder.Append(", parent ").Append(parent);
            }

            builder.Append(") ").Append(TextFormat.Bytes(process.WorkingSetBytes))
                .Append(", ").Append(process.ThreadCount).Append(process.ThreadCount == 1 ? " thread" : " threads");
            if (process.StartTime is { } started)
            {
                builder.Append(", started ").Append(started.ToString("u", System.Globalization.CultureInfo.InvariantCulture));
            }

            if (process.Container is { } container)
            {
                builder.Append(" [").Append(RenderLimits.Printable(container.Runtime)).Append(' ')
                    .Append(RenderLimits.Printable(container.Name ?? ContainerTools.ShortId(container.Id)));
                if (container.ProcessIdInContainer is { } inner)
                {
                    builder.Append(", PID ").Append(inner).Append(" inside");
                }

                builder.Append(']');
            }

            builder.AppendLine();
            if (process.CommandLine is { } commandLine)
            {
                builder.Append("    ").AppendLine(RenderLimits.Printable(commandLine.Length <= 400 ? commandLine : commandLine[..400] + "..."));
            }
        }

        if (redacted > 0)
        {
            builder.Append(redacted).AppendLine(
                " of these had an unreadable command line, which means the server could not access the process, not " +
                "that it was started without arguments. Run the server as root to see them.");
        }

        RenderLimits.NoteElision(builder, rows.Count, "returned processes");
        if (truncated)
        {
            builder.Append("Showing the first ").Append(rows.Count).Append(" of ").Append(totalMatched)
                .Append("; narrow the filter or raise LINUXDIAG_MAX_RESULTS.");
        }

        return builder.ToString().TrimEnd();
    }
}
