using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace LinuxDiag.Mcp.Linux.External;

public sealed record ExternalResult(int ExitCode, string StandardOutput, string StandardError);

public interface IExternalCommand
{
    Task<ExternalResult> RunAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken);
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
    /// Arguments are passed as a list, so there is no shell to inject into -- but a value that starts with '-'
    /// is still read by the program as an option, and a control character has no place in any name.
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
public sealed class LinuxExternalCommand : IExternalCommand
{
    /// <summary>Where programs are taken from, and the child's whole PATH.</summary>
    /// <remarks>
    /// Not the inherited PATH: a root process running whatever an environment variable puts first is how a
    /// planted binary gets run. The capability report's resolver may search PATH; the runner may not.
    /// </remarks>
    internal static readonly string[] SystemDirectories = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"];

    private const int DefaultMaxOutputChars = 32 * 1024 * 1024;
    private readonly int _maxOutputChars;

    public LinuxExternalCommand()
        : this(DefaultMaxOutputChars)
    {
    }

    internal LinuxExternalCommand(int maxOutputChars) => _maxOutputChars = maxOutputChars;

    public async Task<ExternalResult> RunAsync(
        string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(program);
        ArgumentNullException.ThrowIfNull(arguments);

        var path = Resolve(program) ?? throw new ExternalCommandException(
            $"'{program}' is not installed on this machine: it is in none of {string.Join(", ", SystemDirectories)}.");

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
        start.Environment["PATH"] = string.Join(':', SystemDirectories);
        start.Environment["LC_ALL"] = "C.UTF-8";
        start.Environment["SYSTEMD_PAGER"] = "cat";
        start.Environment["PAGER"] = "cat";
        start.Environment["SYSTEMD_COLORS"] = "0";

        using var process = Process.Start(start) ?? throw new ExternalCommandException($"{program} could not be started.");
        process.StandardInput.Close();

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
            Kill(process);
            ProcessStreams.Observe(output);
            ProcessStreams.Observe(error);
            cancellationToken.ThrowIfCancellationRequested();
            throw new ExternalCommandException(
                $"{program} did not finish within {timeout.TotalSeconds:0.#} s and was stopped.", timedOut: true);
        }

        var standardOutput = await ProcessStreams.DrainAsync(output).ConfigureAwait(false);
        var standardError = await ProcessStreams.DrainAsync(error).ConfigureAwait(false);
        if (overflowed)
        {
            throw new ExternalCommandException(
                $"{program} produced more than {_maxOutputChars} characters of output and was stopped; narrow the request. " +
                "A cut-off answer is not returned, because it would read as complete.");
        }

        return new ExternalResult(process.ExitCode, standardOutput, standardError);
    }

    /// <summary>The program's full path in the system directories, or null. A name holding '/' is never resolved.</summary>
    internal static string? Resolve(string program) =>
        program.Contains('/', StringComparison.Ordinal)
            ? null
            : SystemDirectories.Select(directory => Path.Combine(directory, program)).FirstOrDefault(IsExecutable);

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
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
            // Already exited.
        }
    }
}
