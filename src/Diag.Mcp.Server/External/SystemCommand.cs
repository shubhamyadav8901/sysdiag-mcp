using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;

namespace Diag.Mcp.Server.External;

public sealed record ExternalResult(int ExitCode, string StandardOutput, string StandardError);

/// <param name="StoppedEarly">The callback asked to stop; the program was killed before it finished.</param>
public sealed record ExternalLinesResult(int ExitCode, string StandardError, bool StoppedEarly);

public interface IExternalCommand
{
    Task<ExternalResult> RunAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken);

    /// <summary>Runs the program and hands each line of its output to <paramref name="onLine"/>, which returns false to stop it.</summary>
    /// <remarks>For output with no count limit (log show): the caller keeps what it needs and stops the rest.</remarks>
    Task<ExternalLinesResult> RunLinesAsync(
        string program, IReadOnlyList<string> arguments, TimeSpan timeout, Func<string, bool> onLine, CancellationToken cancellationToken);
}

public sealed class ExternalCommandException : Exception, IDiagnosticException
{
    public ExternalCommandException(string message, bool timedOut = false)
        : base(message) => TimedOut = timedOut;

    public ExternalCommandException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>The program ran past its bound and was stopped -- not the same as failing.</summary>
    public bool TimedOut { get; }
}

/// <summary>A value a caller supplied, bound for a program's argument list.</summary>
public static class ExternalArgument
{
    /// <remarks>
    /// <para>Arguments are passed as a list, so there is no shell to inject into -- but a value that starts with '-'
    /// is still read by the program as an option, and a control character has no place in any name.</para>
    /// <para>Necessary, not sufficient: a positional argument also needs the program's own rules. systemctl expands
    /// glob characters in unit names and journalctl reads FIELD=value and '+' as matches, so in LinuxDiag a value
    /// bound for one goes through its unit-name or journal-match parser as well; each server checks its own.</para>
    /// </remarks>
    public static string Check(string? value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{parameterName} is empty.", parameterName);
        }

        if (value.StartsWith('-'))
        {
            throw new ArgumentException($"'{value}' starts with '-', which the program would read as an option.", parameterName);
        }

        if (value.Any(char.IsControl))
        {
            throw new ArgumentException($"{parameterName} contains a control character.", parameterName);
        }

        return value;
    }
}

/// <summary>Runs a system program the way a root server must: by name, from the system directories, bounded.</summary>
/// <remarks>Each server subclasses it with its own directories, locale and program-specific environment.</remarks>
[UnsupportedOSPlatform("windows")]
public class SystemCommand : IExternalCommand
{
    private const int DefaultMaxOutputChars = 32 * 1024 * 1024;

    /// <summary>How long the pipes may stay open after the program exits.</summary>
    private static readonly TimeSpan DrainGrace = TimeSpan.FromSeconds(5);

    /// <summary>Where programs are taken from, and the child's whole PATH.</summary>
    /// <remarks>
    /// Not the inherited PATH: a root process running whatever an environment variable puts first is how a
    /// planted binary gets run. The capability report's resolver may search PATH; the runner may not.
    /// </remarks>
    private readonly string[] _directories;
    private readonly int _maxOutputChars;

    public SystemCommand(IReadOnlyList<string> directories)
        : this(directories, DefaultMaxOutputChars)
    {
    }

    protected SystemCommand(IReadOnlyList<string> directories, int maxOutputChars)
    {
        ArgumentNullException.ThrowIfNull(directories);
        _directories = [.. directories];
        _maxOutputChars = maxOutputChars;
    }

    public IReadOnlyList<string> Directories => _directories;

    /// <summary>The child's LC_ALL. "C" exists everywhere; a server that knows a UTF-8 C locale exists says so.</summary>
    protected virtual string Locale => "C";

    /// <summary>Adds program-specific settings (pagers, colours) to the child's otherwise empty environment.</summary>
    protected virtual void AddEnvironment(IDictionary<string, string?> environment)
    {
    }

    public async Task<ExternalResult> RunAsync(
        string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var process = Start(program, arguments, timeout);

        var overflowed = false;
        void Overflow()
        {
            overflowed = true;
            Kill(process);
        }

        var output = ReadBoundedAsync(process.StandardOutput, _maxOutputChars, Overflow);
        var error = ReadBoundedAsync(process.StandardError, _maxOutputChars, Overflow);

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            ProcessStreams.Observe(output);
            ProcessStreams.Observe(error);
            Kill(process);
            cancellationToken.ThrowIfCancellationRequested();
            throw TimedOut(program, timeout);
        }

        // The kit's drain returns what it has after its grace, which suits run_command. Here the output is parsed
        // as the whole answer, so a pipe a surviving grandchild holds open is an error, not a short answer.
        var drained = Task.WhenAll(output, error);
        if (!ReferenceEquals(await Task.WhenAny(drained, Task.Delay(DrainGrace)).ConfigureAwait(false), drained))
        {
            ProcessStreams.Observe(drained);
            Kill(process);
            throw new ExternalCommandException(
                $"{program} exited, but a process it started left its output open, so the answer may be incomplete and is not returned.");
        }

        var standardOutput = await output.ConfigureAwait(false);
        var standardError = await error.ConfigureAwait(false);
        if (overflowed)
        {
            throw Overflowed(program);
        }

        return new ExternalResult(process.ExitCode, standardOutput, standardError);
    }

    public async Task<ExternalLinesResult> RunLinesAsync(
        string program, IReadOnlyList<string> arguments, TimeSpan timeout, Func<string, bool> onLine, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(onLine);
        using var process = Start(program, arguments, timeout);

        var overflowed = false;
        var error = ReadBoundedAsync(process.StandardError, _maxOutputChars, () => { overflowed = true; Kill(process); });
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);

        var stopped = false;
        var total = 0L;
        try
        {
            while (await process.StandardOutput.ReadLineAsync(deadline.Token).ConfigureAwait(false) is { } line)
            {
                total += line.Length + 1;
                if (total > _maxOutputChars)
                {
                    overflowed = true;
                    break;
                }

                if (!onLine(line))
                {
                    stopped = true;
                    break;
                }
            }

            if (stopped || overflowed)
            {
                Kill(process);
            }

            // Inside the deadline: a program can close its output and keep running.
            await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            ProcessStreams.Observe(error);
            Kill(process);
            cancellationToken.ThrowIfCancellationRequested();
            throw TimedOut(program, timeout);
        }
        finally
        {
            // A callback that throws must not leave the program running.
            if (!process.HasExited)
            {
                ProcessStreams.Observe(error);
                Kill(process);
            }
        }

        var standardError = await ProcessStreams.DrainAsync(error).ConfigureAwait(false);
        if (overflowed)
        {
            throw Overflowed(program);
        }

        return new ExternalLinesResult(stopped ? -1 : process.ExitCode, standardError, stopped);
    }

    private static ExternalCommandException TimedOut(string program, TimeSpan timeout) =>
        new($"{program} did not finish within {timeout.TotalSeconds:0.#} s and was stopped.", timedOut: true);

    private ExternalCommandException Overflowed(string program) =>
        new($"{program} produced more than {_maxOutputChars} characters of output and was stopped; narrow the request. " +
            "A cut-off answer is not returned, because it would read as complete.");

    /// <summary>Starts the program from the system directories with a cleared environment and closed input.</summary>
    private Process Start(string program, IReadOnlyList<string> arguments, TimeSpan timeout)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(program);
        ArgumentNullException.ThrowIfNull(arguments);

        // Before anything starts: CancelAfter would refuse it only once a child was running, and leak that child.
        if (timeout <= TimeSpan.Zero || timeout.TotalMilliseconds > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout), timeout, "The timeout must be positive and under 24 days.");
        }

        var path = Resolve(program, _directories) ?? throw new ExternalCommandException(
            $"'{program}' is not installed on this machine: it is in none of {string.Join(", ", _directories)}.");

        var start = new ProcessStartInfo(path)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        // A clean environment: nothing inherited can change what the program does or where it looks.
        start.Environment.Clear();
        start.Environment["PATH"] = string.Join(':', _directories);
        start.Environment["LC_ALL"] = Locale;
        start.Environment["PAGER"] = "cat";
        AddEnvironment(start.Environment);

        Process process;
        try
        {
            process = Process.Start(start) ?? throw new ExternalCommandException($"{program} could not be started.");
        }
        catch (Win32Exception ex)
        {
            // A noexec mount, a binary apt is replacing (text file busy), a broken interpreter line: say which program.
            throw new ExternalCommandException($"{path} could not be started: {ex.Message}", ex);
        }

        process.StandardInput.Close();
        return process;
    }

    /// <summary>The program's full path in the given directories, or null. A name holding '/' is never resolved.</summary>
    internal static string? Resolve(string program, IReadOnlyList<string> directories) =>
        program.Contains('/', StringComparison.Ordinal)
            ? null
            : directories.Select(directory => Path.Combine(directory, program)).FirstOrDefault(IsExecutable);

    private static bool IsExecutable(string path) =>
        File.Exists(path) &&
        (File.GetUnixFileMode(path) & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) != 0;

    private static async Task<string> ReadBoundedAsync(StreamReader reader, int maxChars, Action overflow)
    {
        var builder = new StringBuilder();
        var buffer = new char[8192];
        int read;
        while ((read = await reader.ReadAsync(buffer).ConfigureAwait(false)) > 0)
        {
            if (builder.Length + read > maxChars)
            {
                overflow();
                return builder.ToString();
            }

            builder.Append(buffer, 0, read);
        }

        return builder.ToString();
    }

    private static void Kill(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or AggregateException)
        {
            // Already exited, or part of the tree could not be killed: either way there is nothing more to do,
            // and the caller must still get this runner's own error rather than this one.
        }
    }
}
