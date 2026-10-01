using System.Diagnostics;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Log;

/// <summary>Recent unified-log events, read backwards in time windows (spec M7).</summary>
/// <remarks>
/// <para>log show prints oldest first and has no count limit, so reading one wide window and keeping its tail would,
/// when a cap fires on a busy Mac, return the oldest events while claiming the newest. Windows are walked newest
/// first instead; within each, a ring keeps only that window's newest matches, and they are committed to the result
/// only once the window was read in full -- a window cut off by the output cap or the timeout has delivered only its
/// oldest lines, so it contributes nothing and the result says its newest events were not reached.</para>
/// </remarks>
public sealed class MacLogInspector(IExternalCommand commands, MacDiagOptions options) : ILogInspector
{
    public const int MaxMinutes = 7 * 24 * 60;

    internal const string PrivateNote = "Some messages read <private>: the system redacts them, and this server cannot reveal them.";
    internal const string LossNote = "The system dropped some log messages in this range, so the record is incomplete.";

    internal Func<DateTimeOffset> Clock { get; init; } = static () => DateTimeOffset.Now;

    public async Task<EventQueryResult> QueryAsync(
        string? process, string? subsystem, string? category, string? sender, int minutes, string[]? levels, int maxEvents,
        CancellationToken cancellationToken)
    {
        if (minutes is < 1 or > MaxMinutes)
        {
            throw new ArgumentOutOfRangeException(nameof(minutes), minutes, $"minutes must be between 1 and {MaxMinutes} (7 days).");
        }

        var types = LogLevels.Parse(levels);
        var predicate = LogPredicate.Build(process, subsystem, category, sender, types);
        var limit = Math.Clamp(maxEvents, 1, options.MaxResults);
        // Whole seconds: --start and --end carry no fraction, so edges kept to the tick would drop an event in an edge
        // second from both the window that filters it out and the one log never gave it to.
        var clock = Clock();
        var now = clock.AddTicks(-(clock.Ticks % TimeSpan.TicksPerSecond));
        var budget = options.ExternalToolTimeout * 3;
        var watch = Stopwatch.StartNew();

        var events = new List<EventEntry>();
        var limitations = new List<string>();
        var sawPrivate = false;
        var sawLoss = false;
        foreach (var (from, to) in LogWindows.For(minutes))
        {
            if (watch.Elapsed > budget)
            {
                limitations.Add($"Stopped after {budget.TotalSeconds:0} s; events older than {from} minutes were not read.");
                break;
            }

            var start = now.AddMinutes(-to);
            var end = now.AddMinutes(-from);
            var room = limit + 1 - events.Count;
            var ring = new Queue<EventEntry>();
            string[] arguments =
            [
                "show", "--style", "ndjson", "--start", LogWindows.Format(start), "--end", LogWindows.Format(end),
                .. types.Contains(LogMessageType.Info) ? ["--info"] : Array.Empty<string>(),
                .. types.Contains(LogMessageType.Debug) ? ["--debug"] : Array.Empty<string>(),
                "--predicate", predicate,
            ];

            try
            {
                var result = await commands.RunLinesAsync("log", arguments, options.ExternalToolTimeout, line =>
                {
                    if (LogNdjson.Parse(line) is not { } parsed || parsed.Timestamp < start || parsed.Timestamp >= end)
                    {
                        return true;
                    }

                    if (parsed.Kind == LogLineKind.Loss)
                    {
                        sawLoss = true;
                        return true;
                    }

                    if (!LogLevels.Includes(types, parsed.MessageType))
                    {
                        return true;
                    }

                    ring.Enqueue(new EventEntry(parsed.Timestamp, LogLevels.SharedName(parsed.MessageType), parsed.MessageType, parsed.Process,
                        parsed.Subsystem, parsed.Category, parsed.Message, parsed.ProcessId));
                    if (ring.Count > room)
                    {
                        ring.Dequeue();
                    }

                    return true;
                }, cancellationToken).ConfigureAwait(false);

                if (result.ExitCode != 0 && !result.StoppedEarly)
                {
                    throw new LogQueryException($"log show failed (exit {result.ExitCode}): {result.StandardError.Trim()}");
                }
            }
            catch (ExternalCommandException ex)
            {
                limitations.Add(
                    $"The newest events between {LogWindows.Format(start)} and {LogWindows.Format(end)} were not reached: the log for that " +
                    $"window was too large or slow to read in full ({ex.Message}). Narrow the filter or the time range.");
                break;
            }

            var window = ring.Reverse().ToList();
            sawPrivate |= window.Any(e => e.Message?.Contains("<private>", StringComparison.Ordinal) == true);
            events.AddRange(window);
            if (events.Count > limit)
            {
                break;
            }
        }

        if (sawPrivate)
        {
            limitations.Add(PrivateNote);
        }

        if (sawLoss)
        {
            limitations.Add(LossNote);
        }

        return new EventQueryResult(minutes, events.Take(limit).ToList(), events.Count > limit, limitations);
    }
}
