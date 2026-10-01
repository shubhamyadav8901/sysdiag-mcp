using System.Collections;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Log;
using MacDiag.Mcp.Mac.Parsers;
using static MacDiag.Mcp.Tests.SystemOverviewTests;

namespace MacDiag.Mcp.Tests;

public sealed class EventLogTests
{
    private static readonly DateTimeOffset Now = new(2024, 10, 1, 12, 0, 0, TimeSpan.Zero);

    private static string Line(int secondsAgo, string type, string message) =>
        $"{{\"timestamp\":\"{Now.AddSeconds(-secondsAgo):yyyy-MM-dd HH:mm:ss.ffffff}+0000\",\"messageType\":\"{type}\",\"eventType\":\"logEvent\"," +
        $"\"processImagePath\":\"/usr/bin/app\",\"senderImagePath\":\"/usr/bin/app\",\"subsystem\":\"\",\"category\":\"\",\"eventMessage\":\"{message}\",\"processID\":1}}";

    /// <summary>log show answered one window at a time, in the order asked; a null answer throws as an overflow would.</summary>
    private static FakeCommands Windows(params string?[] answers)
    {
        var call = 0;
        return new FakeCommands((program, _) =>
        {
            var answer = call < answers.Length ? answers[call] : "";
            call++;
            return answer is null ? throw new ExternalCommandException("log produced more than 33554432 characters of output") : FakeCommands.Ok(answer);
        });
    }

    private static Task<EventQueryResult> Query(FakeCommands commands, int minutes = 60, string[]? levels = null, int maxEvents = 50,
        string? process = null, string? subsystem = null) =>
        new MacLogInspector(commands, MacDiagOptions.FromEnvironment(new Hashtable())) { Clock = () => Now }
            .QueryAsync(process, subsystem, null, null, minutes, levels, maxEvents, CancellationToken.None);

    [Fact]
    public void Only_log_events_are_events_and_their_types_map_to_the_shared_levels()
    {
        var parsed = Fixture(Unverified, "log-ndjson").Split('\n').Select(LogNdjson.Parse).ToList();

        var events = parsed.Where(p => p?.Kind == LogLineKind.Event).Select(p => p!).ToList();
        Assert.Equal(["Default", "Error", "Fault", "Info"], events.Select(e => e.MessageType));
        Assert.Equal(["Warning", "Error", "Critical", "Information"], events.Select(e => LogLevels.SharedName(e.MessageType)));
        Assert.Equal("backup", events[1].Process);
        Assert.Single(parsed, p => p?.Kind == LogLineKind.Loss);
        Assert.Equal(2, parsed.Count(p => p is null)); // the activity event and the trailing count
    }

    [Fact]
    public async Task Events_come_back_newest_first_across_windows()
    {
        var result = await Query(Windows(
            Line(50, "Error", "w1-older") + "\n" + Line(10, "Error", "w1-newer"),
            Line(200, "Error", "w2-older") + "\n" + Line(120, "Error", "w2-newer")));

        Assert.Equal(["w1-newer", "w1-older", "w2-newer", "w2-older"], result.Events.Select(e => e.Message));
        Assert.False(result.Truncated);
    }

    [Fact]
    public async Task A_window_keeps_its_newest_matches_not_its_oldest()
    {
        // log show prints oldest first: keeping the first two would return the oldest while claiming the newest.
        var result = await Query(Windows(string.Join('\n', Line(50, "Error", "a"), Line(40, "Error", "b"), Line(30, "Error", "c"), Line(20, "Error", "d"))), maxEvents: 2);

        Assert.Equal(["d", "c"], result.Events.Select(e => e.Message));
        Assert.True(result.Truncated);
    }

    [Fact]
    public async Task A_window_too_large_to_read_says_its_newest_events_were_not_reached_and_is_not_called_truncated()
    {
        // Review Focus 4.
        var result = await Query(Windows(Line(10, "Error", "first window"), null));

        Assert.Equal(["first window"], result.Events.Select(e => e.Message));
        Assert.False(result.Truncated);
        Assert.Contains(result.Limitations, l => l.Contains("were not reached", StringComparison.Ordinal));
    }

    /// <summary>Delivers the second window's lines, then fails as the output cap would: what a busy Mac does.</summary>
    private sealed class CutOffMidway(string firstWindow, string secondWindowStart) : IExternalCommand
    {
        private int _call;

        public Task<ExternalResult> RunAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<ExternalLinesResult> RunLinesAsync(
            string program, IReadOnlyList<string> arguments, TimeSpan timeout, Func<string, bool> onLine, CancellationToken cancellationToken)
        {
            foreach (var line in (_call++ == 0 ? firstWindow : secondWindowStart).Split('\n'))
            {
                onLine(line);
            }

            return _call == 1
                ? Task.FromResult(new ExternalLinesResult(0, "", StoppedEarly: false))
                : throw new ExternalCommandException("log produced more than 33554432 characters of output");
        }
    }

    [Fact]
    public async Task A_window_cut_off_midway_contributes_none_of_the_oldest_lines_it_had_delivered()
    {
        var commands = new CutOffMidway(Line(10, "Error", "complete window"), Line(290, "Error", "oldest of a window never finished"));

        var result = await new MacLogInspector(commands, MacDiagOptions.FromEnvironment(new Hashtable())) { Clock = () => Now }
            .QueryAsync(null, null, null, null, 60, null, 50, CancellationToken.None);

        Assert.Equal(["complete window"], result.Events.Select(e => e.Message));
    }

    [Fact]
    public async Task A_log_show_that_fails_is_an_error_not_an_empty_answer()
    {
        var commands = new FakeCommands((_, _) => new ExternalResult(64, "", "log: Invalid predicate"));

        var ex = await Assert.ThrowsAsync<LogQueryException>(() => Query(commands));

        Assert.Contains("Invalid predicate", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Levels_filter_after_parsing_and_default_to_critical_and_error()
    {
        var all = string.Join('\n', Line(50, "Default", "chatter"), Line(40, "Error", "err"), Line(30, "Fault", "fault"), Line(20, "Info", "info"));

        Assert.Equal(["fault", "err"], (await Query(Windows(all))).Events.Select(e => e.Message));
        Assert.Equal(["info", "fault", "err", "chatter"], (await Query(Windows(all), levels: ["all"])).Events.Select(e => e.Message));
    }

    [Fact]
    public async Task Info_and_debug_are_asked_of_log_only_when_wanted()
    {
        var plain = Windows("");
        await Query(plain);
        var verbose = Windows("");
        await Query(verbose, levels: ["information", "verbose"]);

        Assert.DoesNotContain("--info", plain.Calls[0].Arguments);
        Assert.Contains("--info", verbose.Calls[0].Arguments);
        Assert.Contains("--debug", verbose.Calls[0].Arguments);
    }

    [Fact]
    public void The_predicate_quotes_each_value_and_carries_the_types_from_the_level_enum_only()
    {
        Assert.Equal(
            "eventType == logEvent AND (messageType == fault OR messageType == error) AND process == \"backup\" AND subsystem == \"com.example.app\"",
            LogPredicate.Build("backup", "com.example.app", null, null, [LogMessageType.Fault, LogMessageType.Error]));
    }

    [Theory]
    [InlineData("back\"up")]
    [InlineData("back\\up")]
    [InlineData("back\nup")]
    [InlineData("")]
    public async Task A_value_that_could_close_its_quotes_is_refused_before_log_runs(string process)
    {
        // Review Focus 1.
        var commands = Windows("");

        await Assert.ThrowsAsync<ArgumentException>(() => Query(commands, process: process));
        Assert.Empty(commands.Calls);
    }

    [Fact]
    public async Task Private_redaction_and_dropped_messages_are_said_once()
    {
        var result = await Query(Windows(Fixture(Unverified, "log-ndjson").Replace("2024-10-01 11:59", "2024-10-01 11:59", StringComparison.Ordinal)), levels: ["all"]);

        Assert.Single(result.Limitations, l => l.Contains("<private>", StringComparison.Ordinal));
        Assert.Single(result.Limitations, l => l.Contains("dropped", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(10081)]
    public async Task Minutes_outside_one_to_seven_days_are_refused(int minutes)
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => Query(Windows(""), minutes: minutes));
    }

    [Fact]
    public void Windows_reach_back_in_growing_steps_to_the_requested_age()
    {
        Assert.Equal([(0, 1), (1, 5), (5, 15), (15, 30), (30, 45)], LogWindows.For(45));
    }
}
