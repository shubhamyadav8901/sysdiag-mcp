using System.ComponentModel;
using System.Globalization;
using System.Text;
using MacDiag.Mcp.Diagnostics.Log;
using ModelContextProtocol.Server;

namespace MacDiag.Mcp.Tools;

/// <summary>Structured result of <c>event_log_tail</c>.</summary>
public sealed record EventLogTailResult(
    string Summary, int Minutes, IReadOnlyList<EventEntry> Events, bool Truncated, IReadOnlyList<string> Limitations);

[McpServerToolType]
public sealed class EventLogTools(ILogInspector log)
{
    private const int MessageChars = 300;

    [McpServerTool(
        Name = "event_log_tail",
        Title = "Recent unified log records",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Read recent records from the macOS unified log, newest first, filtered by age, severity, process, subsystem, " +
        "category and sender. Defaults to the last hour at critical (fault) and error. 'warning' maps to macOS's default " +
        "type, which is most of all logging, so ask for it only with a narrow filter. Use it to find out what the Mac " +
        "complained about around the time of a failure. Looks back at most 7 days. Some messages read <private>; that " +
        "redaction is the system's.")]
    public async Task<EventLogTailResult> EventLogTail(
        [Description("Only records from this process name, for example 'backupd' or 'sshd'")] string? process = null,
        [Description("Only records from this subsystem, for example 'com.apple.TimeMachine'")] string? subsystem = null,
        [Description("Only records in this category, within a subsystem")] string? category = null,
        [Description("Only records from this sender image (library or binary name)")] string? sender = null,
        [Description("How far back to look, in minutes (1-10080)")] int minutes = 60,
        [Description("Severities to include: critical, error, warning, information, verbose, or 'all'. Defaults to critical+error.")] string[]? levels = null,
        [Description("Maximum records to return")] int maxEvents = 50,
        CancellationToken cancellationToken = default)
    {
        var result = await log.QueryAsync(process, subsystem, category, sender, minutes, levels, maxEvents, cancellationToken).ConfigureAwait(false);
        return new EventLogTailResult(Render(result), result.Minutes, result.Events, result.Truncated, result.Limitations);
    }

    internal static string Render(EventQueryResult result)
    {
        var builder = new StringBuilder();
        builder.Append(result.Events.Count).Append(result.Events.Count == 1 ? " record" : " records")
            .Append(" from the last ").Append(result.Minutes).AppendLine(" minutes, newest first");
        foreach (var entry in result.Events.Take(RenderLimits.MaxRenderedRows))
        {
            var message = (entry.Message ?? string.Empty).Split('\n')[0];
            builder.Append("- ").Append(entry.TimeCreated.ToString("u", CultureInfo.InvariantCulture)).Append(' ')
                .Append(RenderLimits.Printable(entry.Level)).Append(' ').Append(RenderLimits.Printable(entry.Provider));
            if (entry.ProcessId is { } pid)
            {
                builder.Append('[').Append(pid).Append(']');
            }

            builder.Append(": ").AppendLine(RenderLimits.Printable(message.Length > MessageChars ? message[..MessageChars] + "…" : message));
        }

        RenderLimits.NoteElision(builder, result.Events.Count, "records");
        if (result.Truncated)
        {
            builder.AppendLine("More records matched than were returned; raise maxEvents or narrow the filter.");
        }

        foreach (var limitation in result.Limitations)
        {
            builder.Append("NOTE: ").AppendLine(RenderLimits.Printable(limitation));
        }

        return builder.ToString().TrimEnd();
    }
}
