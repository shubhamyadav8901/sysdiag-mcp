using System.ComponentModel;
using System.Globalization;
using System.Text;
using LinuxDiag.Mcp.Diagnostics.Journal;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

/// <summary>Structured result of <c>event_log_tail</c>.</summary>
public sealed record EventLogTailResult(
    string Summary, string? Unit, int Minutes, IReadOnlyList<EventEntry> Events, bool Truncated,
    IReadOnlyList<string> Candidates, IReadOnlyList<string> Limitations);

[McpServerToolType]
public sealed class EventLogTools(IJournalInspector journal)
{
    [McpServerTool(
        Name = "event_log_tail",
        Title = "Recent journal records",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Read recent records from the systemd journal, newest first, filtered by age, severity, unit, provider " +
        "(SYSLOG_IDENTIFIER) and raw journal matches. Defaults to the last hour at critical, error and warning. Use " +
        "it to find out what the machine complained about around the time of a failure, or why a service refused " +
        "to start - pass its unit. Without root, or membership of the systemd-journal or adm group, only this " +
        "account's own records are visible, and the result says so.")]
    public async Task<EventLogTailResult> EventLogTail(
        [Description("Only records from this unit, for example 'nginx.service' or 'backup.timer'")] string? unit = null,
        [Description("How far back to look, in minutes")] int minutes = 60,
        [Description("Severities to include: critical, error, warning, information, verbose, or 'all'. Defaults to critical+error+warning.")] string[]? levels = null,
        [Description("Only records from this provider (SYSLOG_IDENTIFIER), for example 'sshd' or 'kernel'")] string? provider = null,
        [Description("Raw journal matches, each FIELD=value, for example _UID=1000 or _COMM=nginx")] string[]? match = null,
        [Description("Maximum records to return")] int maxEvents = 50,
        CancellationToken cancellationToken = default)
    {
        var result = await journal.QueryAsync(unit, minutes, levels, provider, match, maxEvents, cancellationToken).ConfigureAwait(false);
        return new EventLogTailResult(Render(result), result.Unit, result.Minutes, result.Events, result.Truncated, result.Candidates, result.Limitations);
    }

    internal static string Render(EventQueryResult result)
    {
        var builder = new StringBuilder();
        foreach (var limitation in result.Limitations)
        {
            builder.Append("WARNING: ").AppendLine(limitation);
        }

        var where = result.Unit is null ? "the journal" : $"the journal for '{result.Unit}'";
        if (result.Events.Count == 0)
        {
            if (result.Candidates.Count > 0)
            {
                builder.Append("No unit named '").Append(result.Unit).AppendLine("' exists. Did you mean one of these?");
                foreach (var candidate in result.Candidates)
                {
                    builder.Append("- ").AppendLine(candidate);
                }

                return builder.ToString().TrimEnd();
            }

            if (result.Truncated)
            {
                // A level set with a gap is fetched as its range and filtered: the newest records in the range were
                // all at other levels, which says nothing about older ones.
                return builder.Append("The newest records in ").Append(where).Append(" in the last ").Append(result.Minutes)
                    .Append(" minutes were all outside the requested levels, so older matching records may exist. ")
                    .Append("Narrow the window, raise maxEvents, or ask for a contiguous set of levels.").ToString();
            }

            return builder.Append("No matching records in ").Append(where).Append(" in the last ").Append(result.Minutes)
                .Append(" minutes. Widen the window, relax the severity filter, or check the unit name.").ToString();
        }

        builder.Append(result.Events.Count).Append(result.Events.Count == 1 ? " record" : " records").Append(" in ")
            .Append(where).Append(" over the last ").Append(result.Minutes).AppendLine(" minutes, newest first:");
        foreach (var entry in result.Events.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(entry.TimeCreated.ToString("u", CultureInfo.InvariantCulture))
                .Append(" [").Append(entry.Level).Append("] ").Append(entry.Provider);
            if (entry.Unit is { } unit)
            {
                builder.Append(" (").Append(unit).Append(')');
            }

            if (entry.ProcessId is { } pid)
            {
                builder.Append(" PID ").Append(pid);
            }

            builder.AppendLine();
            var first = entry.Message?.Split('\n')[0] ?? "(no message text)";
            builder.Append("    ").AppendLine(first.Length <= 300 ? first : first[..300] + "...");
        }

        RenderLimits.NoteElision(builder, result.Events.Count, "returned records");
        if (result.Truncated)
        {
            builder.Append("More records matched than were returned. Narrow the window or raise maxEvents.");
        }

        return builder.ToString().TrimEnd();
    }
}
