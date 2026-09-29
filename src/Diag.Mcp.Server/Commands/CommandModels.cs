using System.Diagnostics;

namespace Diag.Mcp.Server.Commands;

/// <summary>A command to run on the machine hosting the server.</summary>
/// <param name="CommandLine">The command, interpreted per <paramref name="Shell"/>.</param>
/// <param name="Shell">
/// Which of the server's shells to interpret it with, by the name the server reports it under -- see
/// <see cref="IShellSet"/>.
/// </param>
/// <param name="WorkingDirectory">Where to run it. Null means the server's own directory.</param>
/// <param name="TimeoutSeconds">Override for the per-command budget. Null uses the server default.</param>
public sealed record CommandRequest(
    string CommandLine,
    string Shell,
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

/// <summary>The shells a server offers, and how each one turns a command line into a process.</summary>
/// <remarks>
/// The shell choice is explicit because it changes what the string means: a shell gets pipes,
/// redirection, chaining and built-ins, while running one executable with literal arguments is the only
/// mode where an argument containing spaces or metacharacters is safe from re-parsing. Which shells
/// exist is the server's -- cmd and PowerShell on Windows, sh and bash on Linux -- so the runner only
/// asks. A shell is named by the word the result reports it as.
/// </remarks>
public interface IShellSet
{
    /// <summary>Fills in the executable and arguments for <paramref name="shell"/>.</summary>
    /// <exception cref="CommandExecutionException">When this server has no such shell.</exception>
    void Apply(ProcessStartInfo start, string shell, string commandLine);
}

/// <summary>The runner's one setting: how long a command may run when the caller does not say.</summary>
public sealed record CommandRunnerOptions(TimeSpan DefaultTimeout);
