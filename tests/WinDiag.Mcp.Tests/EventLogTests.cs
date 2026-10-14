using WinDiag.Mcp.Diagnostics.EventLogs;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

public sealed class EventLogXPathTests
{
    [Fact]
    public void Filters_by_age_in_milliseconds()
    {
        var xpath = WindowsEventLogInspector.BuildXPath(60, [], null, []);

        Assert.Contains("timediff(@SystemTime) <= 3600000", xpath);
    }

    [Fact]
    public void Combines_severities_as_alternatives_not_as_a_conjunction()
    {
        // Levels must be OR-ed. AND-ing them matches nothing, and "no errors found" would look like a
        // healthy machine rather than a broken query.
        var xpath = WindowsEventLogInspector.BuildXPath(10, [EventLevel.Critical, EventLevel.Error], null, []);

        Assert.Contains("(Level=1 or Level=2)", xpath);
    }

    [Fact]
    public void Combines_event_ids_as_alternatives()
    {
        var xpath = WindowsEventLogInspector.BuildXPath(10, [], null, [7000, 7011]);

        Assert.Contains("(EventID=7000 or EventID=7011)", xpath);
    }

    [Fact]
    public void Includes_a_provider_filter_when_one_is_given()
    {
        var xpath = WindowsEventLogInspector.BuildXPath(10, [], "Service Control Manager", []);

        Assert.Contains("Provider[@Name='Service Control Manager']", xpath);
    }

    [Fact]
    public void Omits_filters_that_were_not_requested()
    {
        var xpath = WindowsEventLogInspector.BuildXPath(10, [], null, []);

        Assert.DoesNotContain("Level=", xpath);
        Assert.DoesNotContain("Provider", xpath);
        Assert.DoesNotContain("EventID", xpath);
    }

    [Theory]
    [InlineData("Foo' or '1'='1")]
    [InlineData("Foo\"bar")]
    [InlineData("Foo[1]")]
    public void Refuses_a_provider_name_that_could_rewrite_the_query(string provider)
    {
        // Same principle as the external-tool flag guard, applied to a different interpreter: caller
        // text must not be able to change the meaning of an expression the server composed.
        var ex = Assert.Throws<EventLogQueryException>(
            () => WindowsEventLogInspector.BuildXPath(10, [], provider, []));

        Assert.Contains("Refused the provider name", ex.Message);
    }

    [Fact]
    public void Accepts_punctuation_that_appears_in_real_provider_names()
    {
        var xpath = WindowsEventLogInspector.BuildXPath(
            10, [], "Microsoft-Windows-Kernel-Power (Diagnostics)/Operational", []);

        Assert.Contains("Microsoft-Windows-Kernel-Power (Diagnostics)/Operational", xpath);
    }
}

public sealed class EventLevelParsingTests
{
    [Fact]
    public void Defaults_to_the_severities_that_mean_something_is_wrong()
    {
        Assert.Equal(
            [EventLevel.Critical, EventLevel.Error, EventLevel.Warning],
            EventLogTools.ParseLevels(null));

        Assert.Equal(
            [EventLevel.Critical, EventLevel.Error, EventLevel.Warning],
            EventLogTools.ParseLevels([]));
    }

    [Theory]
    [InlineData("error", EventLevel.Error)]
    [InlineData("WARNING", EventLevel.Warning)]
    [InlineData(" Critical ", EventLevel.Critical)]
    public void Accepts_friendly_names_regardless_of_case_or_padding(string input, EventLevel expected)
    {
        Assert.Equal([expected], EventLogTools.ParseLevels([input]));
    }

    [Fact]
    public void Information_also_covers_level_zero_as_event_viewer_does()
    {
        // Providers that declare no level log at Level 0, and Event Viewer shows those as Information.
        // Filtering on Level=4 alone drops them, and the tool then reports a quiet log -- a confident
        // wrong answer rather than a visible mistake.
        var levels = EventLogTools.ParseLevels(["information"]);

        Assert.Contains(EventLevel.Information, levels);
        Assert.Contains(EventLevel.LogAlways, levels);
    }

    [Fact]
    public void All_means_no_severity_filter_at_all()
    {
        // Needs its own keyword: both null and [] have to mean "use the default", so without this
        // there is no way to ask for every severity.
        Assert.Empty(EventLogTools.ParseLevels(["all"]));
        Assert.Empty(EventLogTools.ParseLevels(["error", "ALL"]));
    }

    [Fact]
    public void Does_not_repeat_a_level_requested_twice()
    {
        var levels = EventLogTools.ParseLevels(["information", "information"]);

        Assert.Equal(levels.Distinct().Count(), levels.Count);
    }

    [Fact]
    public void Rejects_an_unknown_severity_with_the_valid_options()
    {
        var ex = Assert.Throws<ArgumentException>(() => EventLogTools.ParseLevels(["catastrophic"]));

        Assert.Contains("critical, error, warning", ex.Message);
    }

    [Fact]
    public void Rejects_a_numeric_severity_that_is_not_a_real_level()
    {
        // Enum.TryParse happily accepts any integer, so "9" would otherwise become an undefined level
        // and silently match nothing.
        Assert.Throws<ArgumentException>(() => EventLogTools.ParseLevels(["9"]));
    }
}

public sealed class EventLogRenderingTests
{
    private static EventEntry Entry(string level = "Error", string message = "The service terminated unexpectedly.") =>
        new(DateTimeOffset.UnixEpoch, 7034, level, "Service Control Manager", message, 640);

    [Fact]
    public void An_empty_result_states_the_filter_that_produced_it()
    {
        // "Nothing found" alone gets read as "nothing happened", which is a different claim entirely.
        var summary = EventLogTools.Render(new EventQueryResult("System", 60, [], false, []));

        Assert.Contains("last 60 minutes", summary);
        Assert.Contains("Widen the window", summary);
    }

    [Fact]
    public void An_unknown_log_name_lists_real_alternatives()
    {
        var summary = EventLogTools.Render(
            new EventQueryResult("Sytsem", 60, [], false, ["System", "Setup"]));

        Assert.Contains("No event log named 'Sytsem'", summary);
        Assert.Contains("- System", summary);
    }

    [Fact]
    public void Records_are_rendered_with_severity_provider_and_id()
    {
        var summary = EventLogTools.Render(new EventQueryResult("System", 30, [Entry()], false, []));

        Assert.Contains("[Error]", summary);
        Assert.Contains("Service Control Manager", summary);
        Assert.Contains("id 7034", summary);
        Assert.Contains("PID 640", summary);
        Assert.Contains("terminated unexpectedly", summary);
    }

    [Fact]
    public void Truncation_is_stated_rather_than_silent()
    {
        var summary = EventLogTools.Render(new EventQueryResult("System", 30, [Entry()], true, []));

        Assert.Contains("More records matched", summary);
    }

    [Fact]
    public void Only_the_first_line_of_a_long_message_reaches_the_summary()
    {
        var multiline = "First line.\r\nSecond line that should not appear.";

        var summary = EventLogTools.Render(
            new EventQueryResult("System", 30, [Entry(message: multiline)], false, []));

        Assert.Contains("First line.", summary);
        Assert.DoesNotContain("Second line", summary);
    }

    /// <summary>Terminal controls before the line break, so cutting a message at its first line leaves them in.</summary>
    private const string Hostile = "\u001b[31m\u202eATTN\nFORGED line";

    [Theory]
    [InlineData("level")]
    [InlineData("provider")]
    [InlineData("message")]
    public void A_records_text_reaches_the_summary_without_a_terminal_control_or_a_forged_line(string field)
    {
        // Whoever registers a provider writes its name and its messages, and a forwarded or imported record
        // carries its level as text. Cutting the message at its first line removed the forged line but never
        // the ESC or the bidirectional override ahead of it.
        var entry = new EventEntry(
            DateTimeOffset.UnixEpoch,
            7034,
            field == "level" ? Hostile : "Error",
            field == "provider" ? Hostile : "Service Control Manager",
            field == "message" ? Hostile : "The service terminated unexpectedly.",
            640);

        var summary = EventLogTools.Render(new EventQueryResult("System", 30, [entry], false, []));

        AssertInert(summary);
        Assert.Contains("ATTN", summary);
    }

    [Fact]
    public void A_mistyped_log_name_and_the_names_offered_instead_carry_no_terminal_control_or_forged_line()
    {
        var summary = EventLogTools.Render(new EventQueryResult(Hostile, 60, [], false, ["System", Hostile]));

        AssertInert(summary);
        Assert.Contains("- System", summary);
    }

    [Fact]
    public void A_quiet_log_named_with_terminal_controls_says_so_without_them()
    {
        var summary = EventLogTools.Render(new EventQueryResult(Hostile, 60, [], false, []));

        AssertInert(summary);
        Assert.Contains("No matching records", summary);
    }

    private static void AssertInert(string summary)
    {
        // Render ends its own lines with AppendLine, which writes "\r\n" on Windows. Checking the raw summary
        // for '\r' failed every multi-line summary on CI's Windows runner while passing on Linux and macOS, so
        // the platform's line ending is taken out first and only a CR the payload smuggled in is left to find.
        var text = summary.Replace(Environment.NewLine, "\n", StringComparison.Ordinal);

        Assert.DoesNotContain(text.Split('\n'), line => line.TrimStart().StartsWith("FORGED", StringComparison.Ordinal));
        Assert.DoesNotContain('\u001b', text);
        Assert.DoesNotContain('\u202e', text);
        Assert.DoesNotContain('\r', text);
    }
}
