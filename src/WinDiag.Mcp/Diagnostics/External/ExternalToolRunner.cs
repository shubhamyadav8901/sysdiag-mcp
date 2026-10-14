using System.Diagnostics;
using System.Globalization;
using System.Text;
using Microsoft.Extensions.Logging;
using WinDiag.Mcp.Configuration;

namespace WinDiag.Mcp.Diagnostics.External;

/// <summary>
/// Runs Sysinternals console tools with a fixed safety policy.
/// </summary>
/// <remarks>
/// The policy, applied to every invocation without exception:
/// <list type="number">
/// <item>Arguments are passed as a vector via <see cref="ProcessStartInfo.ArgumentList"/>, never as a
/// single command string. Windows re-parses a command string through <c>CommandLineToArgvW</c>, which
/// reintroduces quoting bugs the vector form avoids.</item>
/// <item>Caller-supplied values must not look like flags. See <see cref="ToolArgument"/>.</item>
/// <item>The tool's <see cref="ExternalToolPolicy"/> supplies its standard prefix. That prefix is
/// per-tool, not universal: console tools take <c>-accepteula -nobanner</c>, while Procmon does not
/// recognise <c>-nobanner</c> and rejects it with an invisible dialog.</item>
/// <item>The child is bounded by a timeout and killed, with its process tree, if it overruns.</item>
/// </list>
/// </remarks>
public sealed class ExternalToolRunner : IExternalToolRunner
{
    /// <summary>U+FEFF, as it appears once a BOM has been decoded out of the stream.</summary>
    private const char ByteOrderMark = '\uFEFF';

    private readonly IToolLocator _locator;
    private readonly WinDiagOptions _options;
    private readonly ILogger<ExternalToolRunner> _logger;

    static ExternalToolRunner()
    {
        // .NET ships only UTF-8/16, ASCII and Latin1 out of the box, so the ANSI code page below has
        // to be registered before it can be resolved.
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
    }

    public ExternalToolRunner(IToolLocator locator, WinDiagOptions options, ILogger<ExternalToolRunner> logger)
    {
        _locator = locator;
        _options = options;
        _logger = logger;
    }

    public async Task<ExternalToolResult> RunAsync(
        string executableName,
        IReadOnlyList<ToolArgument> arguments,
        ExternalToolPolicy policy,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executableName);
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(policy);

        var executable = _locator.Resolve(executableName);
        var argv = BuildArgumentVector(arguments, policy.StandardArguments);
        var timeout = policy.Timeout ?? _options.ExternalToolTimeout;

        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,

            // stdout follows the tool's policy; stderr stays on the console default. autorunsc writes
            // its data as UTF-16 but its diagnostics as console text, so decoding both the same way
            // would fix one and break the other.
            StandardOutputEncoding = policy.OutputEncoding ?? ConsoleToolEncoding,
            StandardErrorEncoding = ConsoleToolEncoding
        };

        foreach (var argument in argv)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        var stopwatch = Stopwatch.StartNew();

        int processId;
        try
        {
            process.Start();
            processId = process.Id;
        }
        catch (Exception ex)
        {
            throw new ExternalToolException($"Failed to start '{executable}': {ex.Message}", ex);
        }

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        // Read both streams concurrently with the wait. Reading them sequentially deadlocks as soon as
        // a tool fills the stderr pipe buffer while we are still draining stdout.
        var stdoutTask = process.StandardOutput.ReadToEndAsync(CancellationToken.None);
        var stderrTask = process.StandardError.ReadToEndAsync(CancellationToken.None);

        try
        {
            await process.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            KillQuietly(process);
            var partial = await ProcessStreams.DrainAsync(stdoutTask).ConfigureAwait(false);
            ProcessStreams.Observe(stderrTask);
            throw new ToolTimeoutException(executableName, timeout, partial);
        }
        catch (OperationCanceledException)
        {
            KillQuietly(process);
            ProcessStreams.Observe(stdoutTask);
            ProcessStreams.Observe(stderrTask);
            throw;
        }

        // Trimmed here rather than in each parser: a byte-order mark decoded from the stream arrives as
        // a real U+FEFF character, and it would otherwise become part of the first column name -- so
        // every header match fails for a reason that nothing in the visible output shows.
        var stdout = (await ProcessStreams.DrainAsync(stdoutTask).ConfigureAwait(false)).TrimStart(ByteOrderMark);
        var stderr = await ProcessStreams.DrainAsync(stderrTask).ConfigureAwait(false);
        stopwatch.Stop();

        _logger.LogDebug(
            "{Executable} {Arguments} -> exit {ExitCode} in {ElapsedMs}ms",
            executable,
            string.Join(' ', argv),
            process.ExitCode,
            stopwatch.ElapsedMilliseconds);

        return new ExternalToolResult(executable, argv, process.ExitCode, stdout, stderr, stopwatch.Elapsed, processId);
    }

    /// <summary>
    /// Validates provenance and composes the final argument vector.
    /// </summary>
    /// <remarks>Internal so tests can assert the guard directly, not only through a tool call.</remarks>
    internal static IReadOnlyList<string> BuildArgumentVector(IReadOnlyList<ToolArgument> arguments) =>
        BuildArgumentVector(arguments, ExternalToolPolicy.ConsoleTool.StandardArguments);

    internal static IReadOnlyList<string> BuildArgumentVector(
        IReadOnlyList<ToolArgument> arguments,
        IReadOnlyList<string> standardArguments)
    {
        var argv = new List<string>(arguments.Count + standardArguments.Count);
        argv.AddRange(standardArguments);

        foreach (var argument in arguments)
        {
            // default(ToolArgument) has a null Value and reads as server-authored, so it would skip
            // validation and reach ArgumentList as null. Not a guard bypass -- no caller-controlled
            // data can produce it -- but it deserves a clear failure rather than an ArgumentNullException
            // thrown from inside the process launch.
            if (argument.Value is null)
            {
                throw new ExternalToolException(
                    "An uninitialised argument reached the tool runner. Build arguments with " +
                    "ToolArgument.Flag or ToolArgument.Caller.");
            }

            if (argument.IsCallerSupplied)
            {
                Validate(argument.Value);
            }

            argv.Add(argument.Value);
        }

        return argv;
    }


    private static void Validate(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new UnsafeArgumentException(value);
        }

        // The whole guard. A leading '-' or '/' turns data into a switch as far as the target binary's
        // parser is concerned, and some of those switches are destructive.
        if (value[0] is '-' or '/')
        {
            throw new UnsafeArgumentException(value);
        }

        // Control characters cannot appear in a legitimate path, PID or process name, and they make
        // captured output ambiguous to parse.
        foreach (var c in value)
        {
            if (char.IsControl(c))
            {
                throw new UnsafeArgumentException(value);
            }
        }
    }

    /// <summary>The code page Sysinternals console tools actually write to a redirected pipe.</summary>
    /// <remarks>
    /// <strong>ANSI, not OEM.</strong> Measured by holding <c>café-tëst\naïve.txt</c> open and hex-dumping
    /// handle.exe's raw pipe bytes: the path came back as <c>63 61 66 E9 ... 6E 61 EF 76 65</c>.
    /// <c>0xE9</c>/<c>0xEF</c> are <c>é</c>/<c>ï</c> in CP1252 (ANSI) but <c>Θ</c>/<c>∩</c> in CP437
    /// (OEM), so decoding as OEM turns every non-ASCII path into mojibake -- a path the model would
    /// then report and act on, and which does not exist on disk.
    /// Internal so the handle search can compare a process's name with what handle.exe could have written
    /// for it: see <c>PrintedImageWitness</c>.
    /// </remarks>
    internal static Encoding ConsoleToolEncoding
    {
        get
        {
            try
            {
                return Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.ANSICodePage);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
            {
                return Encoding.UTF8;
            }
        }
    }

    private static void KillQuietly(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
        {
            // The process exited between the check and the kill, or the OS refused. Either way there is
            // nothing useful left to do, and the timeout is already being reported to the caller.
        }
    }
}
