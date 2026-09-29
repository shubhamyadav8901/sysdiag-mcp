using System.Diagnostics;
using Diag.Mcp.Server.Capabilities;
using Microsoft.Extensions.Logging;

namespace Diag.Mcp.Server.Commands;

/// <summary>
/// Runs an arbitrary command line on the machine hosting the server.
/// </summary>
/// <remarks>
/// <para>This is the one executor in the server that does <strong>not</strong> go through the
/// Windows server's ExternalToolRunner, and deliberately so. That runner's whole purpose is to refuse a
/// caller value that looks like a flag and to resolve only a fixed set of Sysinternals binaries — the
/// opposite of what "run any command" means. Routing this through it would either defeat the guard or
/// defeat the feature.</para>
/// <para>What it keeps from that runner is the parts that are about not hanging rather than about
/// safety: both pipes are drained concurrently with the wait (a full stderr pipe deadlocks a
/// sequential read), the child is bounded by a timeout and killed with its whole tree, and output is
/// capped so a command that prints a gigabyte cannot flood the caller.</para>
/// <para>Everything dangerous about this tool is governed at registration
/// (the server's command-execution grant, off by default, refused under read-only) rather than here.
/// By the time a request reaches this class the decision to allow arbitrary execution has already been
/// made; its job is only to run the thing and come back.</para>
/// <para>Shared: which shells exist is the server's <see cref="IShellSet"/>.</para>
/// </remarks>
public sealed class CommandRunner : ICommandRunner
{
    /// <summary>Cap on captured output per stream, in characters.</summary>
    /// <remarks>
    /// A build or a verbose tool can emit megabytes; the point of the server's output budgeting is that
    /// no single call can flood the caller. Generous enough for a git log or a Klocwork build summary,
    /// bounded enough that `type bigfile` cannot bury the session. The truncation is reported.
    /// </remarks>
    private const int MaxOutputChars = 100_000;

    private readonly IShellSet _shells;
    private readonly CommandRunnerOptions _options;
    private readonly IPrivilegeProbe _privileges;
    private readonly ILogger<CommandRunner> _logger;

    public CommandRunner(
        IShellSet shells,
        CommandRunnerOptions options,
        IPrivilegeProbe privileges,
        ILogger<CommandRunner> logger)
    {
        _shells = shells;
        _options = options;
        _privileges = privileges;
        _logger = logger;
    }

    public async Task<CommandResult> RunAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (string.IsNullOrWhiteSpace(request.CommandLine))
        {
            throw new CommandExecutionException("The command line is empty. There is nothing to run.");
        }

        var workingDirectory = ResolveWorkingDirectory(request.WorkingDirectory);
        var timeout = ResolveTimeout(request.TimeoutSeconds);
        var startInfo = BuildStartInfo(request, workingDirectory);

        // Logged in full, always. An arbitrary-command tool on an elevated listener must leave a trail
        // of what it was asked to run; stderr is the server's audit channel.
        _logger.LogInformation(
            "run_command [{Shell}] in {WorkingDirectory}: {CommandLine}",
            request.Shell, workingDirectory, request.CommandLine);

        using var process = new Process { StartInfo = startInfo };
        var stopwatch = Stopwatch.StartNew();

        try
        {
            process.Start();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            throw new CommandExecutionException(
                $"Could not start the command: {ex.Message}. Check the shell and working directory.", ex);
        }

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        var stdoutTask = process.StandardOutput.ReadToEndAsync(CancellationToken.None);
        var stderrTask = process.StandardError.ReadToEndAsync(CancellationToken.None);

        var timedOut = false;
        try
        {
            await process.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            KillTree(process);
            throw;
        }
        catch (OperationCanceledException)
        {
            // The command's own budget, not a caller cancel. Kill it and report what it produced;
            // a build that overran is a finding, not an error to hide.
            KillTree(process);
            timedOut = true;
        }

        var stdout = await ProcessStreams.DrainAsync(stdoutTask).ConfigureAwait(false);
        var stderr = await ProcessStreams.DrainAsync(stderrTask).ConfigureAwait(false);
        stopwatch.Stop();

        var exitCode = ExitCodeOf(process, timedOut);

        _logger.LogInformation(
            "run_command exit {ExitCode} in {ElapsedMs}ms (timedOut={TimedOut})",
            exitCode, stopwatch.ElapsedMilliseconds, timedOut);

        var (outText, outTrunc) = Cap(stdout);
        var (errText, errTrunc) = Cap(stderr);

        return new CommandResult(
            CommandLine: request.CommandLine,
            Shell: request.Shell,
            WorkingDirectory: workingDirectory,
            ExitCode: exitCode,
            StandardOutput: outText,
            StandardError: errText,
            OutputTruncated: outTrunc || errTrunc,
            TimedOut: timedOut,
            DurationSeconds: Math.Round(stopwatch.Elapsed.TotalSeconds, 2),
            Elevated: _privileges.IsElevated);
    }

    private ProcessStartInfo BuildStartInfo(CommandRequest request, string workingDirectory)
    {
        var startInfo = new ProcessStartInfo
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = workingDirectory
        };

        _shells.Apply(startInfo, request.Shell, request.CommandLine);

        return startInfo;
    }

    /// <summary>Splits "prog arg arg" into the executable and the remaining argument string.</summary>
    /// <remarks>
    /// Honours a quoted first token so a path with spaces in quotes is treated as one executable.
    /// Public for the shell sets whose no-shell mode runs one executable with literal arguments.
    /// </remarks>
    public static (string Exe, string Args) SplitFirstToken(string commandLine)
    {
        var trimmed = commandLine.Trim();

        if (trimmed.StartsWith('"'))
        {
            var end = trimmed.IndexOf('"', 1);
            if (end > 0)
            {
                return (trimmed[1..end], trimmed[(end + 1)..].TrimStart());
            }
        }

        var space = trimmed.IndexOf(' ');
        return space < 0 ? (trimmed, string.Empty) : (trimmed[..space], trimmed[(space + 1)..].TrimStart());
    }

    private string ResolveWorkingDirectory(string? requested)
    {
        if (string.IsNullOrWhiteSpace(requested))
        {
            return Path.GetDirectoryName(Environment.ProcessPath) ?? Environment.CurrentDirectory;
        }

        var full = Path.GetFullPath(requested.Trim());
        if (!Directory.Exists(full))
        {
            throw new CommandExecutionException(
                $"The working directory '{full}' does not exist. Create it first, or omit it to run in " +
                "the server's own directory.");
        }

        return full;
    }

    private TimeSpan ResolveTimeout(int? requestedSeconds)
    {
        if (requestedSeconds is not { } seconds)
        {
            return _options.DefaultTimeout;
        }

        if (seconds < 1 || seconds > 3600)
        {
            throw new CommandExecutionException(
                $"timeoutSeconds={seconds} is out of range; use 1..3600, or omit it for the server " +
                $"default of {_options.DefaultTimeout.TotalSeconds:0}s.");
        }

        return TimeSpan.FromSeconds(seconds);
    }

    private static int ExitCodeOf(Process process, bool timedOut)
    {
        if (timedOut)
        {
            return -1;
        }

        try
        {
            return process.ExitCode;
        }
        catch (InvalidOperationException)
        {
            return -1;
        }
    }

    private static (string Text, bool Truncated) Cap(string value)
    {
        if (value.Length <= MaxOutputChars)
        {
            return (value, false);
        }

        return (value[..MaxOutputChars] + "\n... [output truncated]", true);
    }

    private void KillTree(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException
                                       or System.ComponentModel.Win32Exception)
        {
            _logger.LogDebug(ex, "run_command: process already gone or refused kill");
        }
    }
}
