namespace WinDiag.Mcp.Diagnostics.Commands;

/// <summary>How to run a command.</summary>
/// <remarks>
/// The shell choice is explicit because it changes what the string means. <c>Cmd</c> and
/// <c>PowerShell</c> get pipes, redirection, chaining and built-ins; <c>None</c> runs a single
/// executable with the remaining words as literal arguments, which is the only mode where an argument
/// containing spaces or metacharacters is safe from re-parsing.
/// </remarks>
public enum CommandShell
{
    /// <summary><c>cmd.exe /c &lt;command&gt;</c>. The default: it is what a person types.</summary>
    Cmd,

    /// <summary><c>powershell.exe -NoProfile -Command &lt;command&gt;</c>.</summary>
    PowerShell,

    /// <summary>Run the first token as an executable, the rest as literal arguments. No shell.</summary>
    None
}

/// <summary>A command to run on the machine hosting the server.</summary>
/// <param name="CommandLine">The command, interpreted per <paramref name="Shell"/>.</param>
/// <param name="Shell">How to interpret it.</param>
/// <param name="WorkingDirectory">Where to run it. Null means the server's own directory.</param>
/// <param name="TimeoutSeconds">Override for the per-command budget. Null uses the server default.</param>
public sealed record CommandRequest(
    string CommandLine,
    CommandShell Shell = CommandShell.Cmd,
    string? WorkingDirectory = null,
    int? TimeoutSeconds = null);

/// <summary>What running a command produced.</summary>
/// <param name="ExitCode">The process exit code. Non-zero is reported, not thrown — a failing command is a result.</param>
/// <param name="StandardOutput">stdout, truncated to a budget. <paramref name="OutputTruncated"/> says whether.</param>
/// <param name="StandardError">stderr, truncated to the same budget.</param>
/// <param name="TimedOut">True when the command was killed for exceeding its budget; the output is partial.</param>
public sealed record CommandResult(
    string CommandLine,
    string Shell,
    string WorkingDirectory,
    int ExitCode,
    string StandardOutput,
    string StandardError,
    bool OutputTruncated,
    bool TimedOut,
    double DurationSeconds,
    bool Elevated);

/// <summary>Runs an arbitrary command on the host. Registered only when explicitly enabled.</summary>
public interface ICommandRunner
{
    Task<CommandResult> RunAsync(CommandRequest request, CancellationToken cancellationToken);
}

/// <summary>Raised when a command could not be started, or its request was malformed.</summary>
/// <remarks>
/// A command that <em>ran</em> and failed is never this — that is a <see cref="CommandResult"/> with a
/// non-zero exit code. This is only for the request itself being unrunnable: an empty command line, a
/// working directory that does not exist, a shell that could not be launched.
/// </remarks>
public sealed class CommandExecutionException : Exception, IDiagnosticException
{
    public CommandExecutionException(string message) : base(message)
    {
    }

    public CommandExecutionException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
