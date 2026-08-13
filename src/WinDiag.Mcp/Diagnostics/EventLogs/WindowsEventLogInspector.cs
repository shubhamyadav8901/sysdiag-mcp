using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.Versioning;

namespace WinDiag.Mcp.Diagnostics.EventLogs;

/// <summary>
/// Reads the event log through <see cref="EventLogReader"/> with a server-composed XPath filter.
/// </summary>
/// <remarks>
/// <para>Choosing the managed reader over Sysinternals <c>psloglist</c> removes a whole class of risk:
/// <c>psloglist -c</c> <em>clears</em> the log and differs from the harmless <c>-s</c> by one
/// character. Here that verb does not exist, so no argument-composition mistake can destroy audit
/// history.</para>
/// <para>The XPath is still built from caller input, so provider names are validated rather than
/// interpolated blindly -- the same principle as the external-tool flag guard, applied to a different
/// interpreter.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsEventLogInspector : IEventLogInspector
{
    private const int MaxCandidates = 25;

    public EventQueryResult Query(
        string log,
        int minutes,
        IReadOnlyList<EventLevel> levels,
        string? provider,
        IReadOnlyList<int> eventIds,
        int maxEvents,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(log);
        ArgumentOutOfRangeException.ThrowIfLessThan(minutes, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxEvents, 1);

        var xpath = BuildXPath(minutes, levels, provider, eventIds);
        var query = new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = true };

        EventLogReader reader;
        try
        {
            reader = new EventLogReader(query);
        }
        catch (EventLogNotFoundException)
        {
            return new EventQueryResult(log, minutes, [], false, ListLogNames(log));
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new EventLogQueryException(
                $"Access denied reading the '{log}' event log. The Security log in particular requires " +
                "administrator rights. Restart the server from an elevated terminal, or query a log " +
                "such as System or Application instead.", ex);
        }

        using (reader)
        {
            var events = new List<EventEntry>();
            var truncated = false;

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                EventRecord? record;
                try
                {
                    record = reader.ReadEvent();
                }
                catch (EventLogException ex)
                {
                    throw new EventLogQueryException(
                        $"Failed while reading the '{log}' event log: {ex.Message}", ex);
                }

                if (record is null)
                {
                    break;
                }

                using (record)
                {
                    if (events.Count >= maxEvents)
                    {
                        truncated = true;
                        break;
                    }

                    events.Add(Describe(record));
                }
            }

            return new EventQueryResult(log, minutes, events, truncated, []);
        }
    }

    private static EventEntry Describe(EventRecord record) =>
        new(
            TimeCreated: record.TimeCreated is { } created ? new DateTimeOffset(created) : default,
            EventId: record.Id,

            // LevelDisplayName resolves the provider's message metadata, so it throws
            // EventLogNotFoundException whenever that provider is not registered on this machine --
            // routine for uninstalled software and third-party components. Letting it escape fails the
            // ENTIRE query because of one record, discarding every other record already read.
            // The numeric level is always present, so the fallback loses nothing that matters.
            Level: SafeRead(() => record.LevelDisplayName, null) ?? DescribeLevel(record.Level),
            Provider: SafeRead(() => record.ProviderName, null) ?? "(unknown)",
            Message: ReadMessage(record),
            ProcessId: SafeRead(() => (int?)record.ProcessId, null));

    /// <summary>
    /// Reads a record property that can throw when its provider's metadata is unavailable.
    /// </summary>
    private static T? SafeRead<T>(Func<T?> read, T? fallback)
    {
        try
        {
            return read();
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException)
        {
            return fallback;
        }
    }

    /// <summary>
    /// Formats the record's message, tolerating a provider whose message resources are unavailable.
    /// </summary>
    /// <remarks>
    /// Uninstalled or third-party providers routinely lack registered message DLLs. Throwing there
    /// would lose every other field of a record that is otherwise perfectly informative.
    /// </remarks>
    private static string? ReadMessage(EventRecord record)
    {
        try
        {
            var message = record.FormatDescription();
            return string.IsNullOrWhiteSpace(message) ? null : message.Trim();
        }
        catch (EventLogException)
        {
            return null;
        }
    }

    private static string DescribeLevel(byte? level) => level switch
    {
        // Level 0 is what providers log when they declare no level, and Event Viewer displays it as
        // Information. Omitting it here would tag exactly the records the level-0 filter fix was
        // written to surface as "(unknown)" -- and those records come overwhelmingly from providers
        // with no registered metadata, which is precisely when this fallback is reached.
        0 => "Information",
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        4 => "Information",
        5 => "Verbose",
        _ => "(unknown)"
    };

    /// <summary>Builds the XPath filter. Internal so the composition can be asserted directly.</summary>
    internal static string BuildXPath(
        int minutes,
        IReadOnlyList<EventLevel> levels,
        string? provider,
        IReadOnlyList<int> eventIds)
    {
        var conditions = new List<string>
        {
            $"TimeCreated[timediff(@SystemTime) <= {(long)minutes * 60_000}]"
        };

        if (levels.Count > 0)
        {
            conditions.Add(Or(levels.Select(level => $"Level={(int)level}")));
        }

        if (!string.IsNullOrWhiteSpace(provider))
        {
            conditions.Add($"Provider[@Name='{ValidateProvider(provider)}']");
        }

        if (eventIds.Count > 0)
        {
            // Event ids are integers, so they cannot carry an injection payload the way a name can.
            conditions.Add(Or(eventIds.Select(id => $"EventID={id.ToString(CultureInfo.InvariantCulture)}")));
        }

        return $"*[System[{string.Join(" and ", conditions)}]]";
    }

    private static string Or(IEnumerable<string> terms) => $"({string.Join(" or ", terms)})";

    /// <summary>
    /// Rejects provider names that could break out of the XPath string literal.
    /// </summary>
    /// <remarks>
    /// A name containing a quote or bracket would let the caller rewrite the filter expression. Real
    /// provider names use letters, digits, spaces and punctuation such as '-', '.', '/', '(' and ')',
    /// none of which are affected by this check.
    /// </remarks>
    private static string ValidateProvider(string provider)
    {
        foreach (var c in provider)
        {
            if (c is '\'' or '"' or '[' or ']' || char.IsControl(c))
            {
                throw new EventLogQueryException(
                    $"Refused the provider name \"{provider}\": quotes, brackets and control characters " +
                    "cannot appear in a real provider name and would alter the query's meaning. " +
                    "Pass the provider's literal name, for example 'Service Control Manager'.");
            }
        }

        return provider;
    }

    private static List<string> ListLogNames(string attempted)
    {
        try
        {
            var names = EventLogSession.GlobalSession.GetLogNames().ToList();

            // Offer near matches first; fall back to the well-known logs when nothing resembles it.
            var similar = names
                .Where(name => name.Contains(attempted, StringComparison.OrdinalIgnoreCase))
                .Order(StringComparer.OrdinalIgnoreCase)
                .Take(MaxCandidates)
                .ToList();

            return similar.Count > 0
                ? similar
                : names.Where(IsCommonLog).Order(StringComparer.OrdinalIgnoreCase).ToList();
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static bool IsCommonLog(string name) =>
        name is "Application" or "System" or "Security" or "Setup"
            or "Microsoft-Windows-Diagnostics-Performance/Operational";
}
