using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.EventLogs;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>event_log_tail</c>.</summary>
public sealed record EventLogTailResult(
    string Summary,
    string Log,
    int Minutes,
    IReadOnlyList<EventEntry> Events,
    bool Truncated,
    IReadOnlyList<string> Candidates);

/// <summary>Windows event log inspection.</summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class EventLogTools
{
    private readonly IEventLogInspector _events;
    private readonly WinDiagOptions _options;

    public EventLogTools(IEventLogInspector events, WinDiagOptions options)
    {
        _events = events;
        _options = options;
    }

    [McpServerTool(
        Name = "event_log_tail",
        Title = "Recent event log records",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Read recent records from a Windows event log, newest first, filtered by age, severity, " +
        "provider and event id. Defaults to the last hour of the System log at Critical, Error and " +
        "Warning. Use it to find out what the machine complained about around the time of a failure, " +
        "or to see why a service refused to start. Reading the Security log requires elevation.")]
    public EventLogTailResult EventLogTail(
        [Description("Log name, for example 'System', 'Application', 'Security', or a channel such as 'Microsoft-Windows-WindowsUpdateClient/Operational'")]
        string log = "System",
        [Description("How far back to look, in minutes")]
        int minutes = 60,
        [Description("Severities to include: critical, error, warning, information, verbose, or 'all'. Defaults to critical+error+warning. 'information' also covers level-0 records, as Event Viewer does.")]
        string[]? levels = null,
        [Description("Only records from this provider, for example 'Service Control Manager'")]
        string? provider = null,
        [Description("Only these event ids")]
        int[]? eventIds = null,
        [Description("Maximum records to return")]
        int maxEvents = 50,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(log);

        if (minutes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(minutes), minutes, "Look-back must be at least one minute.");
        }

        var cappedMaxEvents = Math.Clamp(maxEvents, 1, _options.MaxResults);

        var result = _events.Query(
            log,
            minutes,
            ParseLevels(levels),
            provider,
            eventIds ?? [],
            cappedMaxEvents,
            cancellationToken);

        return new EventLogTailResult(
            Render(result), result.Log, result.Minutes, result.Events, result.Truncated, result.Candidates);
    }

    /// <summary>Maps friendly severity names, defaulting to the three that indicate something is wrong.</summary>
    /// <remarks>
    /// "information" expands to <c>Information</c> <em>and</em> <c>LogAlways</c>, matching what Event
    /// Viewer does. Providers that declare no level log at 0, and those records display as
    /// Information; filtering on 4 alone drops them and the tool then reports a quiet log.
    /// <para>"all" returns an empty list, which the query layer treats as no severity filter at all.
    /// Without an explicit keyword there is no way to ask for everything, because both null and an
    /// empty array have to mean "use the default".</para>
    /// </remarks>
    internal static IReadOnlyList<EventLevel> ParseLevels(string[]? levels)
    {
        if (levels is null || levels.Length == 0)
        {
            return [EventLevel.Critical, EventLevel.Error, EventLevel.Warning];
        }

        var parsed = new List<EventLevel>(levels.Length + 1);

        foreach (var level in levels)
        {
            var name = level?.Trim() ?? string.Empty;

            if (string.Equals(name, "all", StringComparison.OrdinalIgnoreCase))
            {
                return [];
            }

            if (!Enum.TryParse<EventLevel>(name, ignoreCase: true, out var value) || !Enum.IsDefined(value))
            {
                throw new ArgumentException(
                    $"'{level}' is not a severity. Use one or more of: critical, error, warning, " +
                    "information, verbose, or 'all' for every severity.",
                    nameof(levels));
            }

            parsed.Add(value);

            if (value == EventLevel.Information)
            {
                parsed.Add(EventLevel.LogAlways);
            }
        }

        return parsed.Distinct().ToList();
    }

    internal static string Render(EventQueryResult result)
    {
        var builder = new StringBuilder();

        if (result.Candidates.Count > 0)
        {
            builder.Append("No event log named '").Append(RenderLimits.Printable(result.Log)).AppendLine("' exists. Available logs include:");
            foreach (var candidate in result.Candidates)
            {
                builder.Append("- ").AppendLine(RenderLimits.Printable(candidate));
            }

            return builder.ToString().TrimEnd();
        }

        if (result.Events.Count == 0)
        {
            // A quiet log is a real and useful answer, but only if the caller knows the filter that
            // produced it -- otherwise "nothing found" gets read as "nothing happened".
            builder.Append("No matching records in the '").Append(RenderLimits.Printable(result.Log))
                .Append("' log in the last ").Append(result.Minutes)
                .Append(" minutes. Widen the window, relax the severity filter, or check the log name.");
            return builder.ToString();
        }

        builder.Append(result.Events.Count).Append(result.Events.Count == 1 ? " record" : " records")
            .Append(" in the '").Append(RenderLimits.Printable(result.Log)).Append("' log over the last ")
            .Append(result.Minutes).AppendLine(" minutes, newest first:");

        foreach (var entry in result.Events.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(entry.TimeCreated.ToString("u", CultureInfo.InvariantCulture))
                .Append(" [").Append(RenderLimits.Printable(entry.Level)).Append("] ")
                .Append(RenderLimits.Printable(entry.Provider)).Append(" id ").Append(entry.EventId);

            if (entry.ProcessId is { } pid)
            {
                builder.Append(" (PID ").Append(pid).Append(')');
            }

            builder.AppendLine();

            if (entry.Message is { } message)
            {
                builder.Append("    ").AppendLine(FirstLine(message));
            }
        }

        RenderLimits.NoteElision(builder, result.Events.Count, "returned records");

        if (result.Truncated)
        {
            builder.Append("More records matched than were returned. Narrow the window or raise maxEvents.");
        }

        return builder.ToString().TrimEnd();
    }

    /// <summary>
    /// Event messages run to many lines; the first carries the substance.
    /// </summary>
    /// <remarks>
    /// The full text stays in the structured content, so nothing is lost -- this only keeps the
    /// human-readable summary from becoming unreadable at fifty records.
    /// </remarks>
    private static string FirstLine(string message)
    {
        var newline = message.IndexOfAny(['\r', '\n']);

        // Whoever registered the provider wrote the message, so an ESC or a bidirectional override in the
        // first line is theirs too -- cutting at the newline was never the whole defence. Escaped before the
        // length cut, so the budget is measured on what is actually written.
        var line = RenderLimits.Printable(newline < 0 ? message : message[..newline]);
        return line.Length <= 300 ? line : line[..300] + "...";
    }
}
