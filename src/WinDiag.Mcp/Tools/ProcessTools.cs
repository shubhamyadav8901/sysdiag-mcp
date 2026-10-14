using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics.Handles;
using WinDiag.Mcp.Diagnostics.Pipes;
using WinDiag.Mcp.Diagnostics.Processes;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>process_list</c>.</summary>
public sealed record ProcessListToolResult(
    string Summary,
    IReadOnlyList<ProcessInfo> Processes,
    int TotalMatched,
    bool Truncated,
    int CommandLinesRedacted,
    string? Limitation);

/// <summary>Structured result of <c>named_pipes</c>.</summary>
public sealed record NamedPipesResult(
    string Summary,
    IReadOnlyList<NamedPipe> Pipes,
    int TotalMatched,
    bool Truncated);

/// <summary>What is running, and how the running things talk to each other.</summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class ProcessTools
{
    private readonly IProcessInspector _processes;
    private readonly INamedPipeInspector _pipes;
    private readonly IHandleInspector _handles;

    public ProcessTools(IProcessInspector processes, INamedPipeInspector pipes, IHandleInspector handles)
    {
        _processes = processes;
        _pipes = pipes;
        _handles = handles;
    }

    [McpServerTool(
        Name = "process_handles",
        Title = "Everything one process has open",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "List every kernel object one process has open - files, directories, registry keys, sections, " +
        "mutants, events, tokens. " +
        "Use it to answer what a process is actually touching: which log it is writing, which key it " +
        "read at startup, which named object two processes are both holding. It is also the way to " +
        "find the mutant behind a 'already running' refusal, and the file a process is keeping open " +
        "after it should have closed it. " +
        "Scoped to one process, so it is far cheaper than path_handle_search - which has to walk every " +
        "process on the machine - and returns all object types by default for the same reason.")]
    public async Task<PathHandleSearchResult> ProcessHandles(
        [Description("Process id. Get a current one from process_list; PIDs are reused.")]
        int processId,
        [Description(
            "Set false for file references only - file handles plus the mapped sections backing a "
            + "file, which is what handle.exe returns without -a. Faster on a process holding thousands.")]
        bool includeAllObjectTypes = true,
        CancellationToken cancellationToken = default)
    {
        var result = await _handles
            .ListForProcessAsync(processId, includeAllObjectTypes, cancellationToken)
            .ConfigureAwait(false);

        return new PathHandleSearchResult(
            FileLockTools.RenderHandleSummary(result),
            result.Query,
            result.Entries,
            result.Elevated,
            result.Truncated,
            result.TotalMatched,
            result.UnparsedRows);
    }

    [McpServerTool(
        Name = "process_list",
        Title = "Running processes",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "List running processes with their PID, parent PID, start time, memory, thread count and full " +
        "command line. The command line is the point: it is what distinguishes one svchost.exe or one " +
        "service host from another, and it shows the arguments a process was actually launched with. " +
        "Filter by name or command-line substring, or ask for a single PID. Command lines of processes " +
        "owned by other users are only readable when the server is elevated.")]
    public ProcessListToolResult ProcessList(
        [Description("Match this text against the process name or its command line")]
        string? nameFilter = null,
        [Description("Return only this process id")]
        int? processId = null,
        CancellationToken cancellationToken = default)
    {
        var result = _processes.List(nameFilter, processId, cancellationToken);

        return new ProcessListToolResult(
            RenderProcesses(result, nameFilter, processId),
            result.Processes,
            result.TotalMatched,
            result.Truncated,
            result.CommandLinesRedacted,
            result.Limitation);
    }

    [McpServerTool(
        Name = "named_pipes",
        Title = "Named pipes and whether a client can connect",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "List named pipes with how many server instances exist against how many the server allows, " +
        "and, for a pipe whose every instance is created, whether one is listening for a client right " +
        "now. Use it when a client cannot connect to a local service, or hangs connecting, while the " +
        "service itself looks healthy - a pipe with every instance taken and none listening produces " +
        "exactly that, and is invisible from every other angle. Those are marked BUSY and listed first. " +
        "Every instance created is not busy on its own: an instance listens from the moment it is " +
        "created until a client takes it.")]
    public NamedPipesResult NamedPipes(
        [Description("Match this text anywhere in the pipe name, for example a product or service name")]
        string? nameFilter = null,
        CancellationToken cancellationToken = default)
    {
        var result = _pipes.List(nameFilter, cancellationToken);

        return new NamedPipesResult(RenderPipes(result, nameFilter), result.Pipes, result.TotalMatched, result.Truncated);
    }

    internal static string RenderProcesses(ProcessListResult result, string? nameFilter, int? processId)
    {
        var builder = new StringBuilder();

        if (result.Limitation is { } limitation)
        {
            builder.Append("WARNING: ").AppendLine(RenderLimits.Printable(limitation));
        }

        if (result.Processes.Count == 0)
        {
            builder.Append("No process matched");
            if (processId is { } pid)
            {
                builder.Append(" PID ").Append(pid);
            }

            if (!string.IsNullOrWhiteSpace(nameFilter))
            {
                builder.Append(" '").Append(RenderLimits.Printable(nameFilter)).Append('\'');
            }

            builder.Append('.');
            return builder.ToString();
        }

        builder.Append(result.TotalMatched)
            .Append(result.TotalMatched == 1 ? " process" : " processes")
            .AppendLine(":");

        foreach (var process in result.Processes.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(RenderLimits.Printable(process.Name)).Append(" (PID ").Append(process.ProcessId);
            if (process.ParentProcessId is { } parent)
            {
                builder.Append(", parent ").Append(parent);
            }

            builder.Append(") ").Append(FormatBytes(process.WorkingSetBytes))
                .Append(", ").Append(process.ThreadCount).Append(" threads");

            if (process.StartTime is { } started)
            {
                builder.Append(", started ").Append(started.ToString("u", CultureInfo.InvariantCulture));
            }

            builder.AppendLine();

            if (process.CommandLine is { } commandLine)
            {
                // Escaped before it is cut: cut first, a line of control characters escapes to six times the budget.
                builder.Append("    ").AppendLine(Truncate(RenderLimits.Printable(commandLine), 400));
            }
        }

        if (result.CommandLinesRedacted > 0)
        {
            // Without this, a listing of nulls reads as "these processes have no arguments".
            builder.Append(result.CommandLinesRedacted)
                .Append(" of these had an unreadable command line, which means the server could not ")
                .Append("access the process, not that it was started without arguments. ")
                .AppendLine("Run elevated to see them.");
        }

        RenderLimits.NoteElision(builder, result.Processes.Count, "returned processes");

        if (result.Truncated)
        {
            builder.Append("Showing the first ").Append(result.Processes.Count).Append(" of ")
                .Append(result.TotalMatched).Append("; narrow the filter or raise WINDIAG_MAX_RESULTS.");
        }

        return builder.ToString().TrimEnd();
    }

    internal static string RenderPipes(NamedPipeListResult result, string? nameFilter)
    {
        var builder = new StringBuilder();

        if (result.Pipes.Count == 0)
        {
            builder.Append("No named pipes matched");
            if (!string.IsNullOrWhiteSpace(nameFilter))
            {
                builder.Append(" '").Append(RenderLimits.Printable(nameFilter)).Append('\'');
            }

            builder.Append('.');
            return builder.ToString();
        }

        var busy = result.Pipes.Count(p => p.Busy);
        if (busy > 0)
        {
            // Only for a probe that found nothing listening. Every instance merely being created is
            // the normal state of a single-instance pipe waiting for its first client, and calling that
            // a blocked client sent the investigation the wrong way.
            builder.Append("ATTENTION: ").Append(busy)
                .Append(busy == 1 ? " pipe has" : " pipes have")
                .AppendLine(" every instance created and none listening. A client connecting now waits, " +
                            "or gets ERROR_PIPE_BUSY, until the server frees one - normal for a moment " +
                            "between clients, a finding if it persists across calls.");
        }

        builder.Append(result.TotalMatched)
            .Append(result.TotalMatched == 1 ? " named pipe" : " named pipes")
            .AppendLine(":");

        foreach (var pipe in result.Pipes.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(RenderLimits.Printable(pipe.Name)).Append(": ").Append(pipe.InstancesCreated)
                .Append(pipe.Unlimited
                    ? " instances created (no limit)"
                    : $" of {pipe.MaximumInstances} instances created");

            if (pipe.AllInstancesCreated)
            {
                builder.Append(pipe.Listening switch
                {
                    true => ", one listening",
                    false => ", none listening - BUSY",
                    null => ", could not tell whether one is listening"
                });
            }

            builder.AppendLine();
        }

        RenderLimits.NoteElision(builder, result.Pipes.Count, "returned pipes");

        if (result.Truncated)
        {
            builder.Append("Showing the first ").Append(result.Pipes.Count).Append(" of ")
                .Append(result.TotalMatched).Append("; narrow the filter or raise WINDIAG_MAX_RESULTS.");
        }

        return builder.ToString().TrimEnd();
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max] + "...";

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        var unit = 0;

        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value.ToString(unit == 0 ? "0" : "0.#", CultureInfo.InvariantCulture)} {units[unit]}";
    }
}
