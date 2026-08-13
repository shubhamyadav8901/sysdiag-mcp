using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.Activity;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>capture_activity</c>.</summary>
public sealed record CaptureActivityResult(string Summary, ActivityCapture Capture);

/// <summary>Structured result of <c>query_activity</c>.</summary>
public sealed record QueryActivityResult(string Summary, ActivityQueryResult Query);

/// <summary>
/// Recording what the machine is doing. Split from the query tool because capturing loads a kernel
/// driver and writes hundreds of megabytes, so it is dropped in read-only mode — while reading back an
/// existing trace stays available.
/// </summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class ActivityCaptureTools
{
    private readonly IActivityInspector _activity;

    public ActivityCaptureTools(IActivityInspector activity)
    {
        _activity = activity;
    }

    [McpServerTool(
        Name = "capture_activity",
        Title = "Capture file and registry activity",
        ReadOnly = false,
        Destructive = false,
        Idempotent = false,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Record every file and registry operation on this machine for a few seconds, the way Process " +
        "Monitor does, and return where the trace was written plus a summary of what was in it. " +
        "Use it for 'it works on my machine', a program that fails silently, a file it cannot find, or " +
        "a permission problem no ACL explains. " +
        "Reproduce the problem WHILE this runs - it captures a window of time, not history. " +
        "It deliberately returns no events, because a trace holds hundreds of thousands of them; call " +
        "query_activity on the returned csvPath to filter it. Requires administrator rights and loads a " +
        "kernel driver. The .pml also opens directly in the Process Monitor GUI.")]
    public async Task<CaptureActivityResult> CaptureActivity(
        [Description("Seconds to record. Traces grow roughly 5 MB per second, so keep it short and reproduce the problem during the window.")]
        int durationSeconds = 20,
        CancellationToken cancellationToken = default)
    {
        var capture = await _activity.CaptureAsync(durationSeconds, cancellationToken).ConfigureAwait(false);

        return new CaptureActivityResult(ActivityRendering.RenderCapture(capture), capture);
    }
}

/// <summary>Reading back a saved trace. Read-only, so it survives read-only mode.</summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class ActivityQueryTools
{
    private readonly IActivityInspector _activity;
    private readonly WinDiagOptions _options;

    public ActivityQueryTools(IActivityInspector activity, WinDiagOptions options)
    {
        _activity = activity;
        _options = options;
    }

    [McpServerTool(
        Name = "query_activity",
        Title = "Filter a captured activity trace",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Filter a trace saved by capture_activity. This is where the answer usually is: set " +
        "problemsOnly to see only operations that failed - ACCESS DENIED, NAME NOT FOUND, PATH NOT " +
        "FOUND, SHARING VIOLATION - which is exactly what a human does in the Process Monitor GUI. " +
        "Also filters by process, path substring and operation, and always reports the busiest paths " +
        "and processes among the matches so you can see where activity is concentrated.")]
    public QueryActivityResult QueryActivity(
        [Description("The csvPath returned by capture_activity")]
        string capturePath,
        [Description("Only operations that failed in a way worth investigating. Excludes routine results such as FAST IO DISALLOWED.")]
        bool problemsOnly = false,
        [Description("Only this process, matched as a substring of the image name, e.g. 'winword'")]
        string? processName = null,
        [Description("Only this process id")]
        int? processId = null,
        [Description("Only paths containing this text, e.g. a folder or a registry key fragment")]
        string? pathContains = null,
        [Description("Only this operation, e.g. 'CreateFile' or 'RegQueryValue'")]
        string? operation = null,
        [Description("Maximum events to return; the summary counts cover every match regardless")]
        int maxEvents = 100,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(capturePath);

        var filter = new ActivityFilter(
            ProcessName: processName,
            ProcessId: processId,
            PathContains: pathContains,
            Operation: operation,
            ProblemsOnly: problemsOnly,
            MaxEvents: Math.Clamp(maxEvents, 1, _options.MaxResults));

        var result = _activity.Query(capturePath, filter, cancellationToken);

        return new QueryActivityResult(ActivityRendering.RenderQuery(result, filter), result);
    }
}

/// <summary>Rendering shared by the two activity tools.</summary>
internal static class ActivityRendering
{
    internal static string RenderCapture(ActivityCapture capture)
    {
        var builder = new StringBuilder();

        builder.Append("Captured ").Append(capture.DurationSeconds).Append("s of activity: ")
            .Append(Count(capture.TotalEvents)).AppendLine(" events.");

        builder.Append("Trace (opens in the Procmon GUI): ").AppendLine(capture.PmlPath);
        builder.Append("Queryable export: ").AppendLine(capture.CsvPath);

        if (capture.CsvUncPath is { } unc)
        {
            builder.Append("From another machine: ").AppendLine(unc);
        }

        builder.Append(FormatBytes(capture.PmlSizeBytes)).Append(" trace, ")
            .Append(FormatBytes(capture.CsvSizeBytes)).AppendLine(" export.");

        if (capture.TotalEvents == 0)
        {
            // An empty trace is nearly always a setup problem, not a quiet machine.
            builder.AppendLine(
                "No events were recorded at all. That normally means the capture window missed the " +
                "activity, or the trace was filtered to nothing - not that the machine was idle.");
            return builder.ToString().TrimEnd();
        }

        if (capture.ProblemResults.Count > 0)
        {
            // Lead with the failures: this is the reason someone ran a capture.
            builder.AppendLine().AppendLine("Operations that FAILED:");
            foreach (var result in capture.ProblemResults)
            {
                builder.Append("- ").Append(result.Name).Append(": ").Append(Count(result.Count)).AppendLine();
            }

            builder.AppendLine("Call query_activity with problemsOnly to see them.");
        }
        else
        {
            builder.AppendLine().AppendLine("No failed operations were recorded in this window.");
        }

        builder.AppendLine().AppendLine("Busiest processes:");
        foreach (var process in capture.TopProcesses.Take(5))
        {
            builder.Append("- ").Append(process.Name).Append(": ").Append(Count(process.Count)).AppendLine();
        }

        return builder.ToString().TrimEnd();
    }

    internal static string RenderQuery(ActivityQueryResult result, ActivityFilter filter)
    {
        var builder = new StringBuilder();

        builder.Append(Count(result.Matched)).Append(" of ").Append(Count(result.Scanned))
            .Append(" events matched");

        if (filter.ProblemsOnly)
        {
            builder.Append(" (failures only)");
        }

        builder.AppendLine(".");

        if (result.Matched == 0)
        {
            builder.Append("Nothing matched. ");
            builder.Append(filter.ProblemsOnly
                // Distinguishing "no failures" from "no such events" saves a wasted follow-up.
                ? "No operation failed in a way worth investigating. Re-run without problemsOnly to see " +
                  "what the processes were doing at all."
                : "Widen the filter, or check that the capture window actually covered the problem.");
            return builder.ToString();
        }

        builder.AppendLine().AppendLine("Results among matches:");
        foreach (var entry in result.Results.Take(6))
        {
            builder.Append("- ").Append(entry.Name).Append(": ").Append(Count(entry.Count)).AppendLine();
        }

        builder.AppendLine().AppendLine("Busiest paths among matches:");
        foreach (var entry in result.TopPaths.Take(8))
        {
            builder.Append("- ").Append(Count(entry.Count)).Append("x ").AppendLine(Truncate(entry.Name, 160));
        }

        builder.AppendLine().Append("Events");
        if (result.Truncated)
        {
            builder.Append(" (first ").Append(result.Events.Count).Append(')');
        }

        builder.AppendLine(":");

        foreach (var e in result.Events)
        {
            builder.Append("- ").Append(e.Time).Append(' ').Append(e.ProcessName)
                .Append(" (").Append(e.ProcessId).Append(") ").Append(e.Operation)
                .Append(' ').Append(Truncate(e.Path, 160))
                .Append(" -> ").Append(e.Result).AppendLine();
        }

        if (result.Truncated)
        {
            // The counts above are over every match; only this list is capped. Saying so stops the
            // aggregates being read as "top paths among the first hundred".
            builder.Append("Showing ").Append(result.Events.Count).Append(" of ").Append(Count(result.Matched))
                .Append(" matches; the counts above cover all of them. Narrow the filter or raise maxEvents.");
        }

        return builder.ToString().TrimEnd();
    }

    private static string Count(int value) => value.ToString("N0", CultureInfo.InvariantCulture);

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max] + "...";

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        var unit = 0;

        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value.ToString(unit == 0 ? "0" : "0.#", CultureInfo.InvariantCulture)} {units[unit]}";
    }
}
