using System.Globalization;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.External;

namespace WinDiag.Mcp.Diagnostics.Handles;

/// <summary>Exhaustive handle search backed by Sysinternals <c>handle.exe</c>.</summary>
/// <remarks>
/// This is the fallback behind <c>who_locks_path</c>: slower, needs elevation, and requires the
/// Sysinternals Suite to be installed, but it sees every named kernel object rather than only what
/// Restart Manager tracks.
/// </remarks>
public sealed class HandleExeInspector : IHandleInspector
{
    internal const string BaseName = "handle";
    internal const string Executable = BaseName + ".exe";

    /// <summary>
    /// What the 32-bit build does on 64-bit Windows, for the refusal message.
    /// </summary>
    /// <remarks>
    /// Measured on an x64 workstation: <c>handle.exe -u -v System32</c> printed "No matching handles
    /// found." while <c>handle64.exe</c> with the same arguments returned 526 rows. That is the worst
    /// possible failure for this tool -- an empty handle search reads as "nothing holds this file",
    /// which is the answer that ends an investigation.
    /// </remarks>
    private const string WrongArchitectureSymptom =
        "it reports 'No matching handles found.' for every search instead of failing, which reads as " +
        "'nothing holds this file' and would end the investigation there.";

    private readonly IExternalToolRunner _runner;
    private readonly IToolLocator _locator;
    private readonly IPrivilegeProbe _privileges;
    private readonly WinDiagOptions _options;
    private readonly IProcessTable _processes;

    public HandleExeInspector(
        IExternalToolRunner runner,
        IToolLocator locator,
        IPrivilegeProbe privileges,
        WinDiagOptions options,
        IProcessTable processes)
    {
        _runner = runner;
        _locator = locator;
        _privileges = privileges;
        _options = options;
        _processes = processes;
    }

    public async Task<HandleSearchResult> SearchAsync(
        string nameFragment,
        bool includeAllObjectTypes,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nameFragment);

        // Flags are pinned here and nowhere else. handle.exe's CSV row layout is flag-dependent, so
        // composing them at the call site would let the parser and the output drift apart.
        //   -a  ALL object types. Without it handle.exe "will dump all file references" and nothing
        //       else. It is opt-in rather than always-on because it is drastically more expensive:
        //       a machine-wide -a search on an ordinary workstation had emitted 223 rows -- every one
        //       of them still a File -- after 6m40s, against a 120s budget. Always-on would mean the
        //       tool reliably times out instead of reliably answering.
        //   -u  include the owning user
        //   -v  CSV output
        var arguments = new List<ToolArgument>(4);
        if (includeAllObjectTypes)
        {
            arguments.Add(ToolArgument.Flag("-a"));
        }

        arguments.Add(ToolArgument.Flag("-u"));
        arguments.Add(ToolArgument.Flag("-v"));
        arguments.Add(ToolArgument.Caller(nameFragment));

        return await RunAndParseAsync(
                arguments, nameFragment, includeAllObjectTypes, scopedTo: null, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<HandleSearchResult> ListForProcessAsync(
        int processId,
        bool includeAllObjectTypes,
        CancellationToken cancellationToken)
    {
        if (processId <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(processId), processId, "A process id must be positive. Get one from process_list.");
        }

        //   -p  restrict to one process. handle.exe also accepts a NAME here, which would kill the
        //       whole point of taking a PID -- so the value is formatted from an int and never from
        //       caller text, and cannot name more than the one process the caller asked about.
        var arguments = new List<ToolArgument>(5);

        if (includeAllObjectTypes)
        {
            arguments.Add(ToolArgument.Flag("-a"));
        }

        arguments.Add(ToolArgument.Flag("-p"));
        arguments.Add(ToolArgument.Flag(processId.ToString(CultureInfo.InvariantCulture)));
        arguments.Add(ToolArgument.Flag("-u"));
        arguments.Add(ToolArgument.Flag("-v"));

        return await RunAndParseAsync(
                arguments,
                $"PID {processId}",
                includeAllObjectTypes,
                scopedTo: processId,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<HandleSearchResult> RunAndParseAsync(
        IReadOnlyList<ToolArgument> arguments,
        string query,
        bool includeAllObjectTypes,
        int? scopedTo,
        CancellationToken cancellationToken)
    {
        var processScoped = scopedTo is not null;

        var executable = SysinternalsArchitecture.ResolveName(_locator, BaseName, WrongArchitectureSymptom);

        // Read on both sides of the run: a row is confirmed only under a process that was the same
        // process throughout, which one reading cannot show. See PrintedImageWitness.
        var before = _processes.Snapshot();

        var result = await _runner
            .RunAsync(executable, arguments, ExternalToolPolicy.ConsoleTool, cancellationToken)
            .ConfigureAwait(false);

        var printer = result.ProcessId is { } pid ? (pid, Path.GetFileName(result.Executable)) : ((int, string)?)null;
        var images = new PrintedImageWitness(before, _processes.Snapshot(), ExternalToolRunner.ConsoleToolEncoding, printer);

        // handle.exe reports "no matches" via empty output, not an exit code, and writes access-denied
        // diagnostics to stdout alongside data. Only treat it as failed when nothing usable came back.
        if (string.IsNullOrWhiteSpace(result.StandardOutput))
        {
            if (result.ExitCode != 0 && !string.IsNullOrWhiteSpace(result.StandardError))
            {
                throw new ExternalToolException(
                    $"handle.exe exited with code {result.ExitCode} and produced no output: " +
                    result.StandardError.Trim());
            }

            return new HandleSearchResult(
                query, [], _privileges.IsElevated, false, 0, includeAllObjectTypes, processScoped);
        }

        var parsed = HandleCsvParser.Parse(result.StandardOutput, images.IsWhole, scopedTo);
        var entries = parsed.Entries;
        var truncated = entries.Count > _options.MaxResults;

        return new HandleSearchResult(
            Query: query,
            Entries: truncated ? entries.Take(_options.MaxResults).ToArray() : entries,
            Elevated: _privileges.IsElevated,
            Truncated: truncated,
            TotalMatched: entries.Count,
            IncludedAllObjectTypes: includeAllObjectTypes,
            ProcessScoped: processScoped,
            UnparsedRows: parsed.UnparsedRows,
            UnconfirmedImage: parsed.UnconfirmedImage);
    }
}
