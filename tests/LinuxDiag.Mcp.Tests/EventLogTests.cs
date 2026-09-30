using System.Diagnostics;
using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Diagnostics.Journal;
using LinuxDiag.Mcp.Diagnostics.Services;
using LinuxDiag.Mcp.Linux.External;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Tools;

namespace LinuxDiag.Mcp.Tests;

public sealed class EventLogTests
{
    private static readonly LinuxDiagOptions Options = LinuxDiagOptions.FromEnvironment(new System.Collections.Hashtable());
    private static readonly DateTimeOffset Now = new(2026, 10, 3, 12, 0, 0, TimeSpan.Zero);

    private const string Line =
        "{\"__REALTIME_TIMESTAMP\":\"1790785527858577\",\"PRIORITY\":\"3\",\"SYSLOG_IDENTIFIER\":\"app\",\"_PID\":\"675\"," +
        "\"_SYSTEMD_UNIT\":\"app.service\",\"MESSAGE\":\"disk full\"}";

    [Fact]
    public void A_journal_line_gives_time_priority_provider_unit_pid_and_message()
    {
        var (entries, skipped) = JournalJson.Parse(Line + "\n");

        var entry = Assert.Single(entries);
        Assert.Equal(0, skipped);
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1790785527858).AddTicks(5770), entry.Time);
        Assert.Equal(3, entry.Priority);
        Assert.Equal("app", entry.Identifier);
        Assert.Equal("app.service", entry.Unit);
        Assert.Equal(675, entry.ProcessId);
        Assert.Equal("disk full", entry.Message);
    }

    [Fact]
    public void A_message_that_is_bytes_an_array_or_too_large_is_rendered_and_a_broken_line_is_skipped()
    {
        // Review Focus 2: the journal writes a non-UTF-8 message as a byte array, a repeated field as an array,
        // and a value over 4096 bytes as null.
        var (entries, skipped) = JournalJson.Parse(
            "{\"__REALTIME_TIMESTAMP\":\"1\",\"PRIORITY\":\"6\",\"MESSAGE\":[104,105,255]}\n" +
            "{\"__REALTIME_TIMESTAMP\":\"2\",\"PRIORITY\":\"6\",\"MESSAGE\":[\"one\",\"two\"]}\n" +
            "{\"__REALTIME_TIMESTAMP\":\"3\",\"PRIORITY\":\"6\",\"MESSAGE\":null}\n" +
            "{not json\n");

        Assert.Equal("hi�", entries[0].Message);
        Assert.Equal("one\ntwo", entries[1].Message);
        Assert.Null(entries[2].Message);
        Assert.Equal(1, skipped);
    }

    [Fact]
    public void Levels_default_to_critical_error_warning_and_map_to_syslog_priorities()
    {
        Assert.Equal([0, 1, 2, 3, 4], JournalQuery.Priorities(null));
        Assert.Equal([0, 1, 2, 3, 4, 5, 6, 7], JournalQuery.Priorities(["all"]));
        Assert.Equal([5, 6], JournalQuery.Priorities(["information"]));
        Assert.Throws<ArgumentException>(() => JournalQuery.Priorities(["loud"]));
    }

    [Fact]
    public void The_arguments_use_one_priority_range_an_absolute_since_and_validated_matches()
    {
        var arguments = JournalQuery.Arguments(
            "app.service", Now.AddMinutes(-60), JournalQuery.Priorities(["critical", "warning"]), "app", ["_UID=1000"], 51);

        Assert.Equal(
            ["-o", "json", "--no-pager", "-r", "--output-fields=" + JournalQuery.Fields, "-n", "51",
             "--since", "@" + Now.AddMinutes(-60).ToUnixTimeSeconds(), "-p", "0..4", "-u", "app.service",
             "SYSLOG_IDENTIFIER=app", "_UID=1000"],
            arguments);
        Assert.Throws<ArgumentException>(() => JournalQuery.Match("uid=1000"));
        Assert.Throws<ArgumentException>(() => JournalQuery.Match("-f"));
        Assert.Throws<ArgumentException>(() => ServiceNames.CheckUnit("ssh*", "unit"));
    }

    [Fact]
    public async Task A_non_contiguous_level_set_is_filtered_after_the_range_and_other_users_hint_becomes_a_limitation()
    {
        var journal = string.Join("\n",
            Line.Replace("\"PRIORITY\":\"3\"", "\"PRIORITY\":\"4\"", StringComparison.Ordinal),
            Line.Replace("\"PRIORITY\":\"3\"", "\"PRIORITY\":\"2\"", StringComparison.Ordinal),
            Line);
        var commands = new FakeCommands((_, _) => new ExternalResult(0, journal,
            "Hint: You are currently not seeing messages from other users and the system.\n"));

        var result = await new LinuxJournalInspector(commands, new NoServices(), Options, () => Now)
            .QueryAsync(null, 60, ["critical", "warning"], null, null, 50, CancellationToken.None);

        Assert.Equal([4, 2], result.Events.Select(e => e.Priority));
        Assert.Contains(result.Limitations, l => l.Contains("only this account's own records", StringComparison.Ordinal));
    }

    [Fact]
    public async Task One_record_past_the_limit_marks_the_result_truncated()
    {
        var commands = new FakeCommands((_, _) => FakeCommands.Ok(string.Join("\n", Enumerable.Repeat(Line, 3))));

        var result = await new LinuxJournalInspector(commands, new NoServices(), Options, () => Now)
            .QueryAsync(null, 60, null, null, null, 2, CancellationToken.None);

        Assert.Equal(2, result.Events.Count);
        Assert.True(result.Truncated);
        Assert.Contains("More records matched", EventLogTools.Render(result), StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_answer_says_how_to_widen_it_and_an_unknown_unit_lists_near_matches()
    {
        var empty = EventLogTools.Render(new EventQueryResult("app.service", 60, [], false, [], []));
        var unknown = EventLogTools.Render(new EventQueryResult("crond", 60, [], false, ["cron.service"], []));

        Assert.Contains("Widen the window", empty, StringComparison.Ordinal);
        Assert.Contains("No unit named 'crond'", unknown, StringComparison.Ordinal);
        Assert.Contains("cron.service", unknown, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_captured_distro_parses()
    {
        foreach (var distro in ProcParserTests.Distros())
        {
            var (entries, _) = JournalJson.Parse(ProcParserTests.Fixture(distro, "journal.json")!);
            var entry = Assert.Single(entries);
            Assert.Equal(3, entry.Priority);
            Assert.StartsWith("ld-capture-", entry.Identifier, StringComparison.Ordinal);
            Assert.Contains("é", entry.Message, StringComparison.Ordinal);
        }
    }

    [LinuxFact]
    public async Task A_record_this_test_writes_is_found_by_its_provider()
    {
        var tag = $"ld-test-{Guid.NewGuid():N}"[..20];
        using (var logger = Process.Start(new ProcessStartInfo("logger", ["-t", tag, "-p", "user.err", "found me"]))!)
        {
            logger.WaitForExit();
        }

        EventQueryResult? result = null;
        var watch = Stopwatch.StartNew();
        while ((result is null || result.Events.Count == 0) && watch.Elapsed < TimeSpan.FromSeconds(10))
        {
            result = await new LinuxJournalInspector(new LinuxExternalCommand(), new NoServices(), Options)
                .QueryAsync(null, 5, ["error"], tag, null, 10, CancellationToken.None);
            if (result.Events.Count == 0)
            {
                Thread.Sleep(200);
            }
        }

        Assert.Equal("found me", Assert.Single(result!.Events).Message);
    }

    private sealed class NoServices : IServiceInspector
    {
        public Task<ServiceQueryResult> QueryAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult(new ServiceQueryResult(name, null, ["cron.service"]));

        public Task<IReadOnlyList<string>> CandidatesAsync(string query, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<string>>(["cron.service"]);
    }
}
