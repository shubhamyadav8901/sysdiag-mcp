using System.Text;
using WinDiag.Mcp.Diagnostics.Activity;
using WinDiag.Mcp.Diagnostics.External;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// Parses the real Procmon export captured during the spike.
/// </summary>
/// <remarks>
/// The fixture is a genuine 20-second capture from a 32-bit Windows 10 VM running Procmon 4.05, cut down
/// to the rows caused by the spike script's own marker file. Every assertion below is therefore against
/// data Procmon actually produced, not against what its documentation implies it produces — which has
/// been wrong more than once on this project.
/// </remarks>
public sealed class ProcmonCsvReaderTests
{
    private static string FixturePath => Path.Combine(AppContext.BaseDirectory, "Fixtures", "procmon-golden.csv");

    private static List<ActivityEvent> ReadFixture()
    {
        using var reader = ProcmonCsvReader.Open(FixturePath);
        return ProcmonCsvReader.Read(reader, CancellationToken.None).ToList();
    }

    [Fact]
    public void Reads_every_row_of_the_captured_export()
    {
        var events = ReadFixture();

        Assert.Equal(40, events.Count);
        Assert.All(events, e => Assert.NotEqual(0, e.ProcessId));
    }

    [Fact]
    public void Survives_the_utf8_bom_the_export_actually_carries()
    {
        // The file begins EF BB BF. Read without BOM handling, the first header cell becomes
        // "\ufeffTime of Day", so every lookup for that column misses while the rest appear fine —
        // a failure that looks like missing data rather than a bug.
        Assert.Equal(0xEF, File.ReadAllBytes(FixturePath)[0]);

        Assert.All(ReadFixture(), e => Assert.False(string.IsNullOrEmpty(e.Time)));
    }

    [Fact]
    public void Maps_fields_by_header_name_rather_than_position()
    {
        var first = ReadFixture()[0];

        Assert.Equal("powershell.exe", first.ProcessName);
        Assert.Equal(13628, first.ProcessId);
        Assert.Equal("QueryOpen", first.Operation);
        Assert.Contains("windiag-spike-", first.Path);
        Assert.Equal("FAST IO DISALLOWED", first.Result);
    }

    [Fact]
    public void Keeps_a_detail_field_that_contains_commas()
    {
        // Procmon quotes Detail, and it routinely holds comma-separated text such as
        // "AllocationSize: 3,145,728, EndOfFile: ...". Losing the quoting shifts every later field.
        var withDetail = ReadFixture().First(e => e.Operation == "CreateFile");

        Assert.Contains("Desired Access:", withDetail.Detail);
        Assert.Contains(",", withDetail.Detail);
    }

    [Fact]
    public void Refuses_an_export_missing_a_column_it_needs()
    {
        const string csv = "\"Time of Day\",\"Process Name\",\"PID\"\r\n\"1\",\"a.exe\",\"4\"\r\n";

        var ex = Assert.Throws<FormatException>(() =>
            ProcmonCsvReader.Read(new StringReader(csv), CancellationToken.None).ToList());

        Assert.Contains("Operation", ex.Message);
    }

    [Fact]
    public void Treats_routine_results_as_normal_traffic_not_failures()
    {
        // The distinction the whole errors-only view rests on. FAST IO DISALLOWED alone was 6 of the 40
        // captured rows; counting it as a failure buries the results that actually explain a bug.
        Assert.False(ProcmonCsvReader.IsProblem("SUCCESS"));
        Assert.False(ProcmonCsvReader.IsProblem("FAST IO DISALLOWED"));
        Assert.False(ProcmonCsvReader.IsProblem("END OF FILE"));
        Assert.False(ProcmonCsvReader.IsProblem("FILE LOCKED WITH WRITERS"));

        Assert.True(ProcmonCsvReader.IsProblem("ACCESS DENIED"));
        Assert.True(ProcmonCsvReader.IsProblem("NAME NOT FOUND"));
        Assert.True(ProcmonCsvReader.IsProblem("SHARING VIOLATION"));
        Assert.True(ProcmonCsvReader.IsProblem("PATH NOT FOUND"));
    }
}

public sealed class DelimitedTextTests
{
    private static List<List<string>> Read(string text) =>
        DelimitedText.ReadRecords(new StringReader(text), CancellationToken.None).ToList();

    [Fact]
    public void Splits_plain_records()
    {
        var records = Read("a,b,c\r\nd,e,f\r\n");

        Assert.Equal(2, records.Count);
        Assert.Equal(["a", "b", "c"], records[0]);
    }

    [Fact]
    public void Keeps_a_comma_inside_a_quoted_field()
    {
        Assert.Equal(["a", "b,c", "d"], Read("a,\"b,c\",d\n")[0]);
    }

    [Fact]
    public void Understands_a_doubled_quote_escape()
    {
        Assert.Equal(["say \"hi\""], Read("\"say \"\"hi\"\"\"\n")[0]);
    }

    [Fact]
    public void Keeps_a_newline_inside_a_quoted_field_in_the_same_record()
    {
        // A line-based reader would split this into two records and shift every field after it —
        // silent corruption rather than a visible error.
        var records = Read("a,\"line1\nline2\",c\n");

        Assert.Single(records);
        Assert.Equal("line1\nline2", records[0][1]);
    }

    [Fact]
    public void Consumes_a_doubled_quote_split_across_the_internal_buffer_boundary()
    {
        // 8188 is not arbitrary: it places the FIRST character of the doubled quote at buffer[8191],
        // the last slot of the 8 KB read, so the peek for its partner has to come from the next read.
        // A padding of 8190 -- the obvious choice -- puts the field's opening quote there instead,
        // which takes an entirely different branch and passes even with no boundary handling at all.
        var records = Read(new string('x', 8188) + ",\"a\"\"b\",c\n");

        Assert.Equal("a\"b", records[0][1]);
        Assert.Equal("c", records[0][2]);
    }

    [Fact]
    public void Does_not_swallow_the_delimiter_after_a_closing_quote_at_the_buffer_boundary()
    {
        // 8185 places the CLOSING quote at the boundary. The peek must look ahead, find a comma rather
        // than a second quote, and leave that comma unconsumed -- otherwise field 3 is lost.
        var records = Read(new string('x', 8185) + ",\"ab\",c\n");

        Assert.Equal(3, records[0].Count);
        Assert.Equal("ab", records[0][1]);
        Assert.Equal("c", records[0][2]);
    }

    [Fact]
    public void Yields_a_final_record_with_no_trailing_newline()
    {
        Assert.Single(Read("a,b,c"));
    }

    [Fact]
    public void Ignores_blank_lines()
    {
        Assert.Equal(2, Read("a,b\n\n\nc,d\n").Count);
    }
}

public sealed class ActivityQueryTests
{
    private static string FixturePath => Path.Combine(AppContext.BaseDirectory, "Fixtures", "procmon-golden.csv");

    private static ProcmonActivityInspector Inspector() =>
        new(
            new StubExternalToolRunner(),
            new ToolLocator(),
            new WinDiag.Mcp.Configuration.WinDiagOptions(),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ProcmonActivityInspector>.Instance);

    [Fact]
    public void Aggregates_cover_every_match_while_only_the_event_list_is_capped()
    {
        // The contract the rendered output depends on. If a later change capped the counters too,
        // "busiest paths" would silently become "busiest paths among the first two events" -- a
        // different and much weaker claim, presented in identical prose.
        var result = Inspector().Query(FixturePath, new ActivityFilter(MaxEvents: 2), CancellationToken.None);

        Assert.Equal(40, result.Scanned);
        Assert.Equal(40, result.Matched);
        Assert.Equal(2, result.Events.Count);
        Assert.True(result.Truncated);
        Assert.Equal(40, result.TopProcesses.Sum(p => p.Count));
    }

    [Fact]
    public void Reports_no_truncation_when_everything_fits()
    {
        var result = Inspector().Query(FixturePath, new ActivityFilter(MaxEvents: 500), CancellationToken.None);

        Assert.False(result.Truncated);
        Assert.Equal(result.Matched, result.Events.Count);
    }

    [Fact]
    public void Problems_only_narrows_to_the_failures_but_still_scans_everything()
    {
        var result = Inspector().Query(
            FixturePath, new ActivityFilter(ProblemsOnly: true), CancellationToken.None);

        Assert.Equal(40, result.Scanned);

        // The captured fixture holds only routine results, so this legitimately finds nothing --
        // which is exactly the case that must not read as "no activity".
        Assert.Equal(0, result.Matched);
        Assert.All(result.Events, e => Assert.True(ProcmonCsvReader.IsProblem(e.Result)));
    }

    [Fact]
    public void Filters_by_path_fragment()
    {
        var result = Inspector().Query(
            FixturePath, new ActivityFilter(PathContains: "windiag-spike-"), CancellationToken.None);

        Assert.Equal(40, result.Matched);
        Assert.All(result.Events, e => Assert.Contains("windiag-spike-", e.Path));
    }

    [Fact]
    public void Filters_by_a_detail_substring_such_as_disposition()
    {
        // The fixture carries one 'Disposition: OpenIf' among several 'Disposition: Open', so this proves
        // the Detail predicate is applied server-side and discriminates one disposition from another.
        var result = Inspector().Query(
            FixturePath, new ActivityFilter(DetailContains: "Disposition: OpenIf"), CancellationToken.None);

        Assert.Equal(40, result.Scanned);
        Assert.Equal(1, result.Matched);
        Assert.All(result.Events, e => Assert.Contains("OpenIf", e.Detail));
    }

    [Fact]
    public void The_rendered_events_show_the_detail_column()
    {
        // Detail used to be in structuredContent only, so a reader of the summary could not see the
        // disposition they had just filtered on.
        var filter = new ActivityFilter(DetailContains: "Disposition: OpenIf");
        var result = Inspector().Query(FixturePath, filter, CancellationToken.None);

        var summary = WinDiag.Mcp.Tools.ActivityRendering.RenderQuery(result, filter);

        Assert.Contains("Disposition: OpenIf", summary);
    }

    [Fact]
    public void Explains_a_capture_path_that_does_not_exist()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"windiag-absent-{Guid.NewGuid():N}.csv");

        var ex = Assert.Throws<ActivityCaptureException>(
            () => Inspector().Query(missing, new ActivityFilter(), CancellationToken.None));

        Assert.Contains("capture_activity", ex.Message);
    }

    [Fact]
    public void An_empty_problems_only_result_says_so_rather_than_implying_no_activity()
    {
        var result = Inspector().Query(
            FixturePath, new ActivityFilter(ProblemsOnly: true), CancellationToken.None);

        var summary = WinDiag.Mcp.Tools.ActivityRendering.RenderQuery(
            result, new ActivityFilter(ProblemsOnly: true));

        Assert.Contains("No operation failed", summary);
        Assert.Contains("without problemsOnly", summary);
    }
}

public sealed class ActivityFilterTests
{
    private static ActivityEvent Event(
        string process = "winword.exe",
        int pid = 42,
        string operation = "CreateFile",
        string path = @"C:\Users\me\doc.docx",
        string result = "SUCCESS",
        string detail = "") =>
        new("10:00:00", process, pid, operation, path, result, detail);

    [Fact]
    public void An_unfiltered_query_matches_everything()
    {
        Assert.True(ProcmonActivityInspector.Matches(Event(), new ActivityFilter()));
    }

    [Fact]
    public void Problems_only_keeps_failures_and_drops_routine_results()
    {
        var filter = new ActivityFilter(ProblemsOnly: true);

        Assert.True(ProcmonActivityInspector.Matches(Event(result: "ACCESS DENIED"), filter));
        Assert.False(ProcmonActivityInspector.Matches(Event(result: "SUCCESS"), filter));
        Assert.False(ProcmonActivityInspector.Matches(Event(result: "FAST IO DISALLOWED"), filter));
    }

    [Fact]
    public void Matches_a_process_by_substring_and_case_insensitively()
    {
        Assert.True(ProcmonActivityInspector.Matches(Event(), new ActivityFilter(ProcessName: "WINWORD")));
        Assert.False(ProcmonActivityInspector.Matches(Event(), new ActivityFilter(ProcessName: "excel")));
    }

    [Fact]
    public void Matches_an_exact_process_id()
    {
        Assert.True(ProcmonActivityInspector.Matches(Event(pid: 42), new ActivityFilter(ProcessId: 42)));
        Assert.False(ProcmonActivityInspector.Matches(Event(pid: 42), new ActivityFilter(ProcessId: 43)));
    }

    [Fact]
    public void Matches_a_path_fragment_and_an_operation()
    {
        Assert.True(ProcmonActivityInspector.Matches(Event(), new ActivityFilter(PathContains: @"users\me")));
        Assert.True(ProcmonActivityInspector.Matches(Event(), new ActivityFilter(Operation: "createfile")));
        Assert.False(ProcmonActivityInspector.Matches(Event(), new ActivityFilter(Operation: "RegQueryValue")));
    }

    [Fact]
    public void Combines_filters_conjunctively()
    {
        var filter = new ActivityFilter(ProcessName: "winword", Operation: "RegQueryValue");

        Assert.False(ProcmonActivityInspector.Matches(Event(), filter));
    }

    [Fact]
    public void Matches_a_detail_substring_case_insensitively()
    {
        var e = Event(detail: "Desired Access: Generic Write, Disposition: OverwriteIf, ShareMode: None");

        Assert.True(ProcmonActivityInspector.Matches(e, new ActivityFilter(DetailContains: "Disposition: OverwriteIf")));
        Assert.True(ProcmonActivityInspector.Matches(e, new ActivityFilter(DetailContains: "disposition: overwriteif")));
        Assert.False(ProcmonActivityInspector.Matches(e, new ActivityFilter(DetailContains: "Disposition: Supersede")));
    }

    [Fact]
    public void The_detail_filter_separates_a_creating_open_from_a_plain_open()
    {
        // The whole point: keep a CreateFile that CREATES the file, drop one that only opens it - the
        // predicate lives in Detail, so path/operation alone cannot tell them apart.
        var filter = new ActivityFilter(Operation: "CreateFile", DetailContains: "Disposition: OverwriteIf");

        Assert.True(ProcmonActivityInspector.Matches(Event(detail: "Disposition: OverwriteIf"), filter));
        Assert.False(ProcmonActivityInspector.Matches(Event(detail: "Disposition: Open"), filter));
    }
}

public sealed class ActivityToolPolicyTests
{
    [Fact]
    public void A_windowed_tool_gets_only_the_eula_flag()
    {
        // -nobanner is not a Procmon switch. It rejects it with a message box, which under
        // CreateNoWindow is invisible — so the mistake presents as a hang, not an error.
        var argv = ExternalToolRunner.BuildArgumentVector(
            [ToolArgument.Flag("/Quiet")],
            ExternalToolPolicy.Windowed(TimeSpan.FromSeconds(30)).StandardArguments);

        Assert.Equal(["/AcceptEula", "/Quiet"], argv);
        Assert.DoesNotContain("-nobanner", argv);
    }

    [Fact]
    public void A_console_tool_still_gets_the_banner_suppressed()
    {
        var argv = ExternalToolRunner.BuildArgumentVector(
            [ToolArgument.Flag("-v")],
            ExternalToolPolicy.ConsoleTool.StandardArguments);

        Assert.Equal(["-accepteula", "-nobanner", "-v"], argv);
    }

    [Fact]
    public void A_windowed_policy_carries_its_own_timeout()
    {
        // A capture runs for minutes; it cannot share the global per-call budget without loosening it
        // for every other tool.
        Assert.Equal(TimeSpan.FromMinutes(5), ExternalToolPolicy.Windowed(TimeSpan.FromMinutes(5)).Timeout);
        Assert.Null(ExternalToolPolicy.ConsoleTool.Timeout);
    }
}
