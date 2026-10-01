using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Processes;

/// <summary>The process table from ps: the columns and arguments, then each PID's executable, joined by PID.</summary>
/// <remarks>
/// Joined by PID, never by row: a process that exits or starts between the two calls shifts every row after it.
/// One gone before the second call keeps a null path; one born after the first is simply not listed yet.
/// </remarks>
public sealed class MacProcessTable(IExternalCommand commands, MacDiagOptions options) : IProcessTable
{
    public async Task<ProcessTable> ReadAsync(CancellationToken cancellationToken)
    {
        var args = await Run(["-axww", "-o", "pid=,ppid=,uid=,rss=,stat=,lstart=,args="], cancellationToken).ConfigureAwait(false);
        var comm = await Run(["-axww", "-o", "pid=,comm="], cancellationToken).ConfigureAwait(false);

        var (rows, unparsed) = PsTable.ParseArgs(args);
        var paths = PsTable.ParseComm(comm);
        var limitations = new List<string>();
        if (unparsed > 0)
        {
            limitations.Add($"{unparsed} ps line{(unparsed == 1 ? " was" : "s were")} not in the expected shape and {(unparsed == 1 ? "is" : "are")} not listed.");
        }

        if (paths.Duplicates.Count > 0)
        {
            limitations.Add($"ps listed PID {string.Join(", ", paths.Duplicates)} more than once, so {(paths.Duplicates.Count == 1 ? "its" : "their")} executable path is unknown.");
        }

        var processes = rows.Select(row =>
        {
            var command = paths.Commands.GetValueOrDefault(row.ProcessId);
            var name = LastSegment(command) ?? LastSegment(FirstToken(row.Arguments)) ?? string.Empty;
            return new ProcessRecord(
                row.ProcessId, row.ParentProcessId, name, row.State, row.Start, row.StartText, row.ResidentKiB * 1024, row.UserId,
                command is not null && command.StartsWith('/') ? command : null,
                row.Arguments.Length > 0 ? row.Arguments : null);
        }).ToList();

        return new ProcessTable(processes, limitations);
    }

    private async Task<string> Run(string[] arguments, CancellationToken cancellationToken)
    {
        var result = await commands.RunAsync("ps", arguments, options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        return result.ExitCode == 0
            ? result.StandardOutput
            : throw new ProcessQueryException($"ps failed (exit {result.ExitCode}): {result.StandardError.Trim()}");
    }

    private static string? FirstToken(string arguments) =>
        arguments.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries) is [var first, ..] ? first : null;

    private static string? LastSegment(string? path) =>
        string.IsNullOrEmpty(path) ? null : path[(path.TrimEnd('/').LastIndexOf('/') + 1)..].TrimEnd('/') is { Length: > 0 } last ? last : null;
}
