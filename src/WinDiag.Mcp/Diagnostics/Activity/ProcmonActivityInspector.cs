using System.Globalization;
using System.Reflection;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.Dumps;
using WinDiag.Mcp.Diagnostics.External;

namespace WinDiag.Mcp.Diagnostics.Activity;

/// <summary>Captures file and registry activity by driving Process Monitor in batch mode.</summary>
/// <remarks>
/// Every constant here comes from a measured run on a 32-bit Windows 10 VM with Procmon 4.05, not from
/// the documentation — see the spike results in the plan. The switches do not compose, so a capture is
/// two processes: one to record, a second to export.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class ProcmonActivityInspector : IActivityInspector
{
    /// <summary>Longest capture allowed. Procmon's own ceiling is 3600s; volume makes that absurd.</summary>
    /// <remarks>Measured ~5.5 MB/s of PML unfiltered, so five minutes is already about 1.6 GB.</remarks>
    public const int MaxDurationSeconds = 300;

    public const int MinDurationSeconds = 1;

    /// <summary>
    /// Slack added to the capture duration before the runner gives up.
    /// </summary>
    /// <remarks>
    /// Measured: a 20s capture took 25–26s wall, the extra going on driver load and the final flush.
    /// A tight margin would kill healthy captures.
    /// </remarks>
    private static readonly TimeSpan CaptureOverhead = TimeSpan.FromSeconds(90);

    /// <summary>Export is not bounded by the capture duration; a large trace takes minutes.</summary>
    private static readonly TimeSpan ExportTimeout = TimeSpan.FromMinutes(15);

    /// <summary>How long to wait for the backing file to appear before concluding the driver failed.</summary>
    private static readonly TimeSpan BackingFileGrace = TimeSpan.FromSeconds(20);

    private const string ConfigResource = "WinDiag.Mcp.Resources.windiag.pmc";
    private const int TopCount = 10;

    private readonly IExternalToolRunner _runner;
    private readonly IToolLocator _locator;
    private readonly WinDiagOptions _options;
    private readonly ILogger<ProcmonActivityInspector> _logger;

    /// <summary>One capture at a time: Procmon is a single global instance with one kernel driver.</summary>
    private readonly SemaphoreSlim _oneAtATime = new(1, 1);

    public ProcmonActivityInspector(
        IExternalToolRunner runner,
        IToolLocator locator,
        WinDiagOptions options,
        ILogger<ProcmonActivityInspector> logger)
    {
        _runner = runner;
        _locator = locator;
        _options = options;
        _logger = logger;
    }

    public async Task<ActivityCapture> CaptureAsync(int durationSeconds, CancellationToken cancellationToken)
    {
        if (durationSeconds is < MinDurationSeconds or > MaxDurationSeconds)
        {
            throw new ArgumentOutOfRangeException(
                nameof(durationSeconds),
                durationSeconds,
                $"Capture duration must be {MinDurationSeconds}..{MaxDurationSeconds} seconds. Traces grow " +
                "at roughly 5 MB per second, so longer captures are usually a filtering problem rather " +
                "than a duration one.");
        }

        var executable = ResolveProcmon();

        if (!await _oneAtATime.WaitAsync(TimeSpan.Zero, cancellationToken).ConfigureAwait(false))
        {
            throw new ActivityCaptureException(
                "A capture is already running. Procmon is a single global instance with one kernel " +
                "driver, so only one can run at a time. Wait for the current one to finish.");
        }

        try
        {
            Directory.CreateDirectory(_options.ArtifactDirectory);

            var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
            var pml = Path.Combine(_options.ArtifactDirectory, $"activity_{stamp}.pml");
            var csv = Path.Combine(_options.ArtifactDirectory, $"activity_{stamp}.csv");
            var (config, isTemporary) = ResolveConfiguration();

            try
            {
                await CaptureToBackingFile(executable, config, pml, durationSeconds, cancellationToken)
                    .ConfigureAwait(false);

                await ExportToCsv(executable, config, pml, csv, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                // Only clean up what we extracted; an operator-supplied config is not ours to delete.
                if (isTemporary)
                {
                    TryDelete(config);
                }
            }

            return Summarise(pml, csv, durationSeconds, cancellationToken);
        }
        finally
        {
            _oneAtATime.Release();
        }
    }

    private async Task CaptureToBackingFile(
        string executable, string config, string pml, int durationSeconds, CancellationToken cancellationToken)
    {
        ToolArgument[] arguments =
        [
            ToolArgument.Flag("/Quiet"),
            ToolArgument.Flag("/Minimized"),

            // Pins the filter set. Deliberately NOT combined with /NoFilter, which would clear the stock
            // exclusions ($Mft, pagefile.sys, IRP_MJ_/FASTIO_ noise) that keep volume survivable.
            ToolArgument.Flag("/LoadConfig"),
            ToolArgument.Flag(config),

            ToolArgument.Flag("/BackingFile"),
            ToolArgument.Flag(pml),

            // The only self-terminating mechanism. /Terminate does NOT compose here: it means
            // "kill every ProcMon instance and exit", so putting it on this command line captures nothing.
            ToolArgument.Flag("/Runtime"),
            ToolArgument.Flag(durationSeconds.ToString(CultureInfo.InvariantCulture))
        ];

        var policy = ExternalToolPolicy.Windowed(TimeSpan.FromSeconds(durationSeconds) + CaptureOverhead);

        var capture = _runner.RunAsync(executable, arguments, policy, cancellationToken);

        try
        {
            await GuardAgainstSilentDriverFailure(pml, capture, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Critical: abandoning the capture here would leave Procmon running with its driver loaded
            // for the rest of its budget. The next call would then hit "Another version of the Process
            // Monitor driver is already loaded" -- the guard would have MANUFACTURED the exact failure
            // it exists to detect. Stop it, and do not release the one-at-a-time gate until it is gone.
            await AbortCapture(executable, capture).ConfigureAwait(false);
            throw;
        }

        var result = await capture.ConfigureAwait(false);
        _logger.LogDebug("procmon capture exited {ExitCode} after {Elapsed}", result.ExitCode, result.Duration);

        if (!File.Exists(pml))
        {
            throw new ActivityCaptureException(
                $"The capture produced no trace file. Procmon exited with code {result.ExitCode}. " +
                DriverAdvice);
        }
    }

    /// <summary>
    /// Fails fast when the trace file never appears, which is how a driver failure presents.
    /// </summary>
    /// <remarks>
    /// <para>Procmon reports "Another version of the Process Monitor driver is already loaded" in a
    /// <em>message box</em>. Launched with <c>CreateNoWindow</c> that dialog is invisible, so the call
    /// would otherwise sit until the full timeout with nothing to show for it.</para>
    /// <para>Checking that the file <em>appears</em>, not that it grows. Procmon preallocates the
    /// backing file — measured at exactly 134,217,728 bytes during a capture that finished at
    /// 106,525,338 — so it is full size immediately and then <em>shrinks</em> on close. A
    /// growth check would report every healthy capture as stalled.</para>
    /// </remarks>
    private static async Task GuardAgainstSilentDriverFailure(
        string pml, Task<ExternalToolResult> capture, CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + BackingFileGrace;

        while (DateTime.UtcNow < deadline)
        {
            if (File.Exists(pml))
            {
                return;
            }

            if (capture.IsCompleted)
            {
                // Exited before writing anything: let the caller report the exit code.
                return;
            }

            await Task.Delay(250, cancellationToken).ConfigureAwait(false);
        }

        throw new ActivityCaptureException(
            $"Procmon did not begin writing '{pml}' within {BackingFileGrace.TotalSeconds:0}s. " + DriverAdvice);
    }

    /// <summary>Stops a capture we are giving up on, and waits for it to actually be gone.</summary>
    /// <remarks>
    /// <c>/Terminate</c> is the documented way to stop another instance, and the spike measured it as
    /// synchronous — it returned in 4.6s with the trace file already at its final size. Both awaits are
    /// best-effort: this runs while an exception is in flight, and the original failure is the one worth
    /// reporting.
    /// </remarks>
    private async Task AbortCapture(string executable, Task<ExternalToolResult> capture)
    {
        try
        {
            await _runner.RunAsync(
                    executable,
                    [ToolArgument.Flag("/Terminate")],
                    ExternalToolPolicy.Windowed(TimeSpan.FromMinutes(2)),
                    CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("could not terminate the abandoned capture: {Reason}", ex.Message);
        }

        try
        {
            await capture.ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Observed deliberately: an abandoned task's exception would otherwise surface later as an
            // unhandled one, far from the code that caused it.
            _logger.LogDebug("abandoned capture ended with {Reason}", ex.Message);
        }
    }

    private const string DriverAdvice =
        "The usual cause is its kernel driver failing to load — most often because a different " +
        "Sysinternals build's PROCMON driver is already resident, which Procmon reports in a dialog box " +
        "that is invisible to an unattended caller and which requires a reboot to clear. Check that the " +
        "server is elevated, then reboot the machine if the problem persists.";

    private async Task ExportToCsv(
        string executable, string config, string pml, string csv, CancellationToken cancellationToken)
    {
        // A separate process, because "The /SaveAs option is valid only when used with /OpenLog".
        ToolArgument[] arguments =
        [
            ToolArgument.Flag("/Quiet"),
            ToolArgument.Flag("/Minimized"),
            ToolArgument.Flag("/LoadConfig"),
            ToolArgument.Flag(config),
            ToolArgument.Flag("/OpenLog"),
            ToolArgument.Flag(pml),

            // Without this the configuration's exclusions are loaded and then ignored: Procmon's filter
            // is a DISPLAY filter, so /SaveAs writes every captured event regardless. Measured on a
            // real capture before this flag was added - 126,015 of 228,949 exported events were
            // Procmon observing itself, including 1,077 operations on its own backing file, and 25,322
            // were the IRP_MJ_ traffic the stock filter excludes.
            ToolArgument.Flag("/SaveApplyFilter"),

            ToolArgument.Flag("/SaveAs"),
            ToolArgument.Flag(csv)
        ];

        var result = await _runner
            .RunAsync(executable, arguments, ExternalToolPolicy.Windowed(ExportTimeout), cancellationToken)
            .ConfigureAwait(false);

        if (!File.Exists(csv))
        {
            throw new ActivityCaptureException(
                $"Procmon exported no CSV from '{pml}' (exit code {result.ExitCode}). The trace itself " +
                "is still on disk and can be opened in the Procmon GUI.");
        }
    }

    /// <summary>One streaming pass for the headline numbers.</summary>
    private ActivityCapture Summarise(string pml, string csv, int durationSeconds, CancellationToken cancellationToken)
    {
        var total = 0;
        var problems = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var processes = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        using (var reader = ProcmonCsvReader.Open(csv))
        {
            foreach (var e in ProcmonCsvReader.Read(reader, cancellationToken))
            {
                total++;
                Increment(processes, e.ProcessName);

                if (ProcmonCsvReader.IsProblem(e.Result))
                {
                    Increment(problems, e.Result);
                }
            }
        }

        return new ActivityCapture(
            PmlPath: pml,
            PmlUncPath: MiniDumpWriter.ToAdminShare(pml),
            CsvPath: csv,
            CsvUncPath: MiniDumpWriter.ToAdminShare(csv),
            PmlSizeBytes: Length(pml),
            CsvSizeBytes: Length(csv),
            DurationSeconds: durationSeconds,
            TotalEvents: total,
            ProblemResults: Top(problems),
            TopProcesses: Top(processes));
    }

    public ActivityQueryResult Query(string capturePath, ActivityFilter filter, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(capturePath);
        ArgumentNullException.ThrowIfNull(filter);

        var full = Path.GetFullPath(capturePath);
        if (!File.Exists(full))
        {
            throw new ActivityCaptureException(
                $"'{full}' does not exist. Pass the csvPath returned by capture_activity.");
        }

        var scanned = 0;
        var matched = 0;
        var events = new List<ActivityEvent>(Math.Min(filter.MaxEvents, 1000));
        var paths = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var processes = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var results = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        using (var reader = ProcmonCsvReader.Open(full))
        {
            foreach (var e in ProcmonCsvReader.Read(reader, cancellationToken))
            {
                scanned++;

                if (!Matches(e, filter))
                {
                    continue;
                }

                matched++;
                Increment(paths, e.Path);
                Increment(processes, e.ProcessName);
                Increment(results, e.Result);

                // Aggregates cover every match; only the event list is capped. Truncating the counts
                // too would make "top paths" mean "top paths among the first N", which is a different
                // and much less useful claim.
                if (events.Count < filter.MaxEvents)
                {
                    events.Add(e);
                }
            }
        }

        return new ActivityQueryResult(
            CapturePath: full,
            Scanned: scanned,
            Matched: matched,
            Truncated: matched > events.Count,
            Events: events,
            TopPaths: Top(paths),
            TopProcesses: Top(processes),
            Results: Top(results));
    }

    internal static bool Matches(ActivityEvent e, ActivityFilter filter)
    {
        if (filter.ProblemsOnly && !ProcmonCsvReader.IsProblem(e.Result))
        {
            return false;
        }

        if (filter.ProcessId is { } pid && e.ProcessId != pid)
        {
            return false;
        }

        if (!Contains(e.ProcessName, filter.ProcessName)
            || !Contains(e.Path, filter.PathContains)
            || !Contains(e.Operation, filter.Operation))
        {
            return false;
        }

        return true;
    }

    private static bool Contains(string value, string? needle) =>
        string.IsNullOrWhiteSpace(needle) || value.Contains(needle, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Picks a Procmon that can actually capture on this OS, verifying its architecture.
    /// </summary>
    /// <remarks>
    /// <para>The two distributions differ in a way that silently breaks the capture. The Store package
    /// ships a single <c>Procmon.exe</c> that <em>is</em> the x64 image. The downloadable zip ships
    /// <c>Procmon.exe</c> as a <strong>32-bit launcher</strong> that extracts and starts
    /// <c>Procmon64.exe</c> and then exits immediately.</para>
    /// <para>Running the launcher on x64 would therefore look like a capture that finished in about a
    /// second: the child creates and preallocates the trace file, so the file-exists check passes, and
    /// the export then reads a <c>.pml</c> that is still being written — reporting "0 events" as a
    /// success and blaming the user's capture window.</para>
    /// <para>Hence the PE machine check rather than trusting the file name: a name cannot distinguish
    /// the two, and getting it wrong produces a plausible wrong answer instead of an error.</para>
    /// </remarks>
    private string ResolveProcmon() =>
        SysinternalsArchitecture.ResolveName(
            _locator,
            "Procmon",
            "it only extracts and launches the 64-bit build and then exits, so the capture looks like it " +
            "finished in a second over a trace that is still being written, and reports 0 events as a " +
            "success.");

    /// <summary>
    /// Resolves the Procmon configuration for <c>/LoadConfig</c>, preferring one placed on disk.
    /// </summary>
    /// <returns>The path to use, and whether it is a temporary file the caller must delete.</returns>
    /// <remarks>
    /// <para>The configuration is embedded so a single-file publish carries it, but a
    /// <c>windiag.pmc</c> sitting beside the server overrides it. That matters because the filter set
    /// is the one part of this that genuinely needs tuning per environment, and PMC is an undocumented
    /// binary format only the Procmon GUI can author — so without an override, every filter change
    /// would mean a rebuild and a redeploy of a 90 MB executable.</para>
    /// <para>Learned from a real trace: a configuration exported while Procmon's filters were cleared
    /// carried no exclusions at all, and 52% of the resulting capture was Procmon observing itself.</para>
    /// </remarks>
    private (string Path, bool IsTemporary) ResolveConfiguration()
    {
        var directory = Path.GetDirectoryName(Environment.ProcessPath);
        if (!string.IsNullOrEmpty(directory))
        {
            var beside = Path.Combine(directory, "windiag.pmc");
            if (File.Exists(beside))
            {
                _logger.LogInformation("using the Procmon configuration at {Path}", beside);
                return (beside, false);
            }
        }

        var path = Path.Combine(Path.GetTempPath(), $"windiag-{Guid.NewGuid():N}.pmc");

        using var resource = typeof(ProcmonActivityInspector).Assembly.GetManifestResourceStream(ConfigResource)
            ?? throw new ActivityCaptureException(
                $"The embedded Procmon configuration '{ConfigResource}' is missing from this build.");

        using (var file = File.Create(path))
        {
            resource.CopyTo(file);
        }

        return (path, true);
    }

    private static void Increment(Dictionary<string, int> counts, string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return;
        }

        counts[key] = counts.TryGetValue(key, out var existing) ? existing + 1 : 1;
    }

    private static List<ActivityCount> Top(Dictionary<string, int> counts) =>
        counts.OrderByDescending(pair => pair.Value)
            .ThenBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Take(TopCount)
            .Select(pair => new ActivityCount(pair.Key, pair.Value))
            .ToList();

    private static long Length(string path) => File.Exists(path) ? new FileInfo(path).Length : 0;

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A stray temp file is not worth failing a capture over.
        }
    }
}
