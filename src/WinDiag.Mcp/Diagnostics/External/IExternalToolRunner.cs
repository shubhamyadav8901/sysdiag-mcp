namespace WinDiag.Mcp.Diagnostics.External;

/// <summary>The outcome of one external tool invocation.</summary>
/// <param name="Executable">Full path actually executed.</param>
/// <param name="Arguments">The argument vector as passed, for logging and test assertions.</param>
/// <param name="ProcessId">
/// The PID the tool ran as, which was its own for the whole run; null where no process was started.
/// </param>
public sealed record ExternalToolResult(
    string Executable,
    IReadOnlyList<string> Arguments,
    int ExitCode,
    string StandardOutput,
    string StandardError,
    TimeSpan Duration,
    int? ProcessId = null);

/// <summary>Runs a bundled console tool and captures its output.</summary>
/// <remarks>
/// This is the single choke point for leaving the process. Timeouts, encoding, EULA handling, and the
/// caller-argument safety check all live behind it, so no caller has to remember any of them.
/// </remarks>
public interface IExternalToolRunner
{
    /// <param name="policy">
    /// How this particular tool must be invoked. Defaults to the console-tool convention; a windowed
    /// tool such as Procmon needs a different prefix and its own timeout.
    /// </param>
    Task<ExternalToolResult> RunAsync(
        string executableName,
        IReadOnlyList<ToolArgument> arguments,
        ExternalToolPolicy policy,
        CancellationToken cancellationToken);
}
