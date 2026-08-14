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

    public HandleExeInspector(
        IExternalToolRunner runner,
        IToolLocator locator,
        IPrivilegeProbe privileges,
        WinDiagOptions options)
    {
        _runner = runner;
        _locator = locator;
        _privileges = privileges;
        _options = options;
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

        var executable = SysinternalsArchitecture.ResolveName(_locator, BaseName, WrongArchitectureSymptom);

        var result = await _runner
            .RunAsync(executable, arguments, ExternalToolPolicy.ConsoleTool, cancellationToken)
            .ConfigureAwait(false);

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
                nameFragment, [], _privileges.IsElevated, false, 0, includeAllObjectTypes);
        }

        var entries = HandleCsvParser.Parse(result.StandardOutput);
        var truncated = entries.Count > _options.MaxResults;

        return new HandleSearchResult(
            Query: nameFragment,
            Entries: truncated ? entries.Take(_options.MaxResults).ToArray() : entries,
            Elevated: _privileges.IsElevated,
            Truncated: truncated,
            TotalMatched: entries.Count,
            IncludedAllObjectTypes: includeAllObjectTypes);
    }
}
