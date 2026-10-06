using System.Text;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.Autostart;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// The parser, against output captured from autorunsc 14.3 on a real machine.
/// </summary>
/// <remarks>
/// The fixture is UTF-16 LE with a BOM because that is what autorunsc writes -- storing it as UTF-8
/// would quietly remove the single most surprising property of this tool's output, and the test would
/// then pass against a parser that could never read the real thing.
/// </remarks>
public sealed class AutorunscCsvParserTests
{
    private static string Fixture()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", "autorunsc-l-s-t.csv");

        // Read as the runner does: decode UTF-16, then drop the BOM the decode leaves behind.
        var text = File.ReadAllText(path, Encoding.Unicode);
        return text.TrimStart('\uFEFF');
    }

    private static List<AutostartEntry> Parsed() => AutorunscCsvParser.Parse(Fixture()).Entries;

    /// <summary>autorunsc 14.3's header with <c>-s</c>, exactly as the fixture carries it.</summary>
    private const string SignedHeader =
        "Time,Entry Location,Entry,Enabled,Category,Profile,Description,Signer,Company,Image Path,Version,Launch String\r\n";

    /// <summary>
    /// The HKCU Run row an unprivileged user can plant, in autorunsc's shape, with the value name supplied.
    /// </summary>
    private static string UserRunRow(string entryField) =>
        $"20260801-101500,HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,{entryField},enabled,Logon," +
        "CONTOSO\\jdoe,,(Not verified) (Not Verified) ,(Not Verified) ," +
        "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe,,\"\"\"C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe\"\"\"\r\n";

    /// <summary>A whole row a hostile value name would smuggle in: Windows' own tray icon, signed.</summary>
    private const string ForgedRow =
        "20240401-072632,HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,SecurityHealth,enabled,Logon," +
        "System-wide,Windows Security notification icon,(Verified) Microsoft Windows,(Verified) Microsoft Windows," +
        "C:\\Windows\\system32\\SecurityHealthSystray.exe,10.0.26100.1,%windir%\\system32\\SecurityHealthSystray.exe";

    [Fact]
    public void Reads_the_captured_output()
    {
        var entries = Parsed();

        Assert.NotEmpty(entries);
        Assert.Contains(entries, e => e.Entry == "rdpclip");
        Assert.Contains(entries, e => e.Category == "Scheduled Tasks");
    }

    [Fact]
    public void Drops_the_section_headers_autoruns_emits_for_every_location()
    {
        // Autoruns writes a row for each location it examined, entry name empty, including the ones
        // that held nothing. Reported as entries they read as autostarts with no name and no image.
        // The fixture contains one; 15 of 254 rows were these in the capture it came from.
        Assert.DoesNotContain(Parsed(), e => string.IsNullOrWhiteSpace(e.Entry));
    }

    [Fact]
    public void Separates_the_verdict_from_the_publisher()
    {
        var rdpclip = Parsed().Single(e => e.Entry == "rdpclip");

        Assert.Equal("Verified", rdpclip.SignatureVerdict);

        // Not "(Verified) Microsoft Windows": leaving the prefix on makes every publisher name
        // unmatchable and buries the verdict in a field nobody reads as one.
        Assert.Equal("Microsoft Windows", rdpclip.Company);
    }

    [Fact]
    public void Does_not_invent_a_publisher_called_not_verified()
    {
        // autorunsc writes "(Not verified) (Not Verified)" for an unsigned entry -- the placeholder it
        // already put in Company, prefixed a second time. Returned as a publisher it would read in a
        // report as though something had been signed by it.
        var unsigned = Parsed().Single(e => e.SignatureVerdict == "Not verified");

        Assert.Null(unsigned.Company);
    }

    [Fact]
    public void Keeps_a_description_that_contains_commas_intact()
    {
        // The scheduled-task descriptions are prose and routinely contain commas, so autorunsc quotes
        // those fields. A naive split reads most of a capture correctly and then shifts every column
        // on exactly the rows carrying the most text.
        var withCommas = Parsed().Where(e => e.Description is { } d && d.Contains(',')).ToList();

        Assert.NotEmpty(withCommas);
        Assert.All(withCommas, e => Assert.False(string.IsNullOrWhiteSpace(e.ImagePath)));
        Assert.All(withCommas, e => Assert.DoesNotContain("Verified", e.Description!));
    }

    [Fact]
    public void Reads_the_normalised_utc_timestamp()
    {
        // -t is always passed because the default is a locale-formatted local time: a capture wrote
        // "01-04-2024 12:56:32", which is either 1 April or 4 January, and nothing says which.
        var stamped = Parsed().Where(e => e.Timestamp is not null).ToList();

        Assert.NotEmpty(stamped);
        Assert.All(stamped, e => Assert.Equal(TimeSpan.Zero, e.Timestamp!.Value.Offset));
    }

    [Theory]
    [InlineData("20260731-085743", 2026, 7, 31, 8, 57, 43)]
    [InlineData("20240101-000000", 2024, 1, 1, 0, 0, 0)]
    public void Parses_the_documented_timestamp_shape(
        string value, int year, int month, int day, int hour, int minute, int second)
    {
        var parsed = AutorunscCsvParser.ParseTimestamp(value);

        Assert.Equal(new DateTimeOffset(year, month, day, hour, minute, second, TimeSpan.Zero), parsed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("01-04-2024 12:56:32")]
    public void Returns_no_timestamp_rather_than_guessing_an_ambiguous_one(string value)
    {
        // Null beats a coin flip between 1 April and 4 January.
        Assert.Null(AutorunscCsvParser.ParseTimestamp(value));
    }

    [Fact]
    public void Refuses_output_whose_columns_it_does_not_recognise()
    {
        // A missing column read as empty turns "this entry has no image on disk" -- a real finding --
        // into noise, so a changed format must fail loudly rather than degrade.
        var wrong = "Time,Entry Location,Entry,Enabled\r\n20260101-000000,HKLM\\X,thing,enabled\r\n";

        var ex = Assert.Throws<FormatException>(() => AutorunscCsvParser.Parse(wrong));

        Assert.Contains("Category", ex.Message);
        Assert.Contains("Image Path", ex.Message);
    }

    [Fact]
    public void Says_so_when_no_header_arrived_at_all()
    {
        var ex = Assert.Throws<FormatException>(
            () => AutorunscCsvParser.Parse("Access is denied.\r\nsomething else\r\n"));

        // Naming the encoding matters: decoded as UTF-8, autorunsc's real output produces exactly this
        // failure, and nothing visible in it points at the cause.
        Assert.Contains("UTF-16", ex.Message);
    }

    [Fact]
    public void Returns_nothing_for_empty_output_rather_than_failing()
    {
        Assert.Empty(AutorunscCsvParser.Parse(string.Empty).Entries);
    }

    [Fact]
    public void Finds_no_malformed_rows_in_the_real_capture()
    {
        // The guard below must not cry wolf on ordinary output, or the warning it raises stops meaning
        // anything. Every row of the 14.3 capture has the header's twelve fields.
        Assert.Equal(0, AutorunscCsvParser.Parse(Fixture()).MalformedRows);
    }

    [Fact]
    public void Keeps_a_quoted_description_that_spans_lines_as_one_entry()
    {
        // A version resource's FileDescription may contain a line break, and autorunsc quotes the field
        // like any other. Split into lines first, this record became two fragments: the first ended in
        // an open quote and the second was a row of nonsense, and the real entry was gone.
        var csv = SignedHeader +
                  "20260625-162027,HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,Contoso Agent,enabled," +
                  "Logon,System-wide,\"Contoso agent\r\nsecond line\",(Verified) Contoso Ltd,(Verified) Contoso Ltd," +
                  "C:\\Program Files\\Contoso\\agent.exe,3.25.0.0,\"C:\\Program Files\\Contoso\\agent.exe\"\r\n";

        var parsed = AutorunscCsvParser.Parse(csv);

        var entry = Assert.Single(parsed.Entries);
        Assert.Equal("Contoso Agent", entry.Entry);
        Assert.Equal("Contoso agent\r\nsecond line", entry.Description);
        Assert.Equal(@"C:\Program Files\Contoso\agent.exe", entry.ImagePath);
        Assert.Equal("Verified", entry.SignatureVerdict);
        Assert.Equal(0, parsed.MalformedRows);
    }

    [Fact]
    public void A_value_name_carrying_a_newline_and_a_whole_row_does_not_forge_a_signed_entry()
    {
        // The attack: an unprivileged user names an HKCU Run value "\n" + a complete row describing
        // Windows' own signed tray icon. autorunsc quotes the field. Split on '\n' first, the real
        // record's first line ended in an open quote, its Entry read as empty and it was dropped as a
        // section header -- the unsigned payload vanished -- and the smuggled row was reported as a
        // Verified Microsoft entry, so the summary said every entry was validly signed.
        var csv = SignedHeader + UserRunRow("\"\n" + ForgedRow + "\"");

        var parsed = AutorunscCsvParser.Parse(csv);

        var entry = Assert.Single(parsed.Entries);
        Assert.Equal(@"C:\Users\jdoe\AppData\Local\Temp\payload.exe", entry.ImagePath);
        Assert.Equal("Not verified", entry.SignatureVerdict);
        Assert.DoesNotContain(parsed.Entries, e => e.ImagePath?.Contains("SecurityHealthSystray") == true);
    }

    [Fact]
    public void A_record_broken_by_an_unquoted_newline_is_counted_not_dropped()
    {
        // If a build of autorunsc ever writes the newline without quoting the field, no parser can put
        // the record back together -- but it can refuse to let the fragments pass as a short, clean
        // list. Each piece has the wrong number of fields, and that is reported.
        var csv = SignedHeader + UserRunRow("\n" + ForgedRow);

        var parsed = AutorunscCsvParser.Parse(csv);

        Assert.True(parsed.MalformedRows > 0, "the broken record was dropped without a trace");
    }

    [Fact]
    public void A_row_with_no_entry_name_but_an_image_is_counted_rather_than_taken_for_a_section_header()
    {
        // A section header is a location with nothing in it: no entry, no image, no signer. A row with
        // an empty Entry that still names an image is not one of those, and dropping it silently is how
        // a real autostart disappears.
        var csv = SignedHeader + UserRunRow(string.Empty);

        var parsed = AutorunscCsvParser.Parse(csv);

        Assert.Empty(parsed.Entries);
        Assert.Equal(1, parsed.MalformedRows);
    }

    [Fact]
    public void Splits_the_file_not_found_marker_out_of_the_image_path()
    {
        // Autoruns writes prose into a path field. Left there it matches no filter, attracts no
        // signature verdict, and renders as though nothing were wrong.
        var (path, missing) = AutorunscCsvParser.SplitImagePath("File not found: atmfd.dll");

        Assert.True(missing);
        Assert.Equal("atmfd.dll", path);
    }

    [Fact]
    public void Leaves_a_real_path_alone()
    {
        var (path, missing) = AutorunscCsvParser.SplitImagePath(@"C:\Windows\System32dpclip.exe");

        Assert.False(missing);
        Assert.Equal(@"C:\Windows\System32dpclip.exe", path);
    }

    [Fact]
    public void Reports_no_path_and_no_marker_for_an_empty_image_column()
    {
        var (path, missing) = AutorunscCsvParser.SplitImagePath("   ");

        Assert.False(missing);
        Assert.Null(path);
    }
}

public sealed class AutostartCategoryTests
{
    [Theory]
    [InlineData("all", "*")]
    [InlineData("logon", "l")]
    [InlineData("services", "s")]
    [InlineData("office", "o")]
    [InlineData("logon,services", "ls")]
    [InlineData(" logon , scheduledtasks ", "lt")]
    [InlineData("LOGON,logon", "l")]
    public void Maps_friendly_names_onto_autoruns_letters(string input, string expected)
    {
        Assert.Equal(expected, AutostartTools.ParseCategories(input));
    }

    [Fact]
    public void Treats_all_as_subsuming_anything_it_is_combined_with()
    {
        // autorunsc rejects '*' alongside letters, and "all plus logon" is only a longer way of
        // saying all.
        Assert.Equal("*", AutostartTools.ParseCategories("logon,all,services"));
    }

    [Fact]
    public void Refuses_a_name_it_does_not_know_instead_of_passing_it_through()
    {
        // This is the only place caller text influences the argument vector, and it never reaches it:
        // an unmapped name is rejected rather than forwarded.
        var ex = Assert.Throws<ArgumentException>(() => AutostartTools.ParseCategories("everything"));

        Assert.Contains("is not a category", ex.Message);
        Assert.Contains("scheduledtasks", ex.Message);
    }

    [Fact]
    public void Refuses_something_shaped_like_a_switch()
    {
        Assert.Throws<ArgumentException>(() => AutostartTools.ParseCategories("-m"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Falls_back_to_everything_when_nothing_was_asked_for(string input)
    {
        Assert.Equal("*", AutostartTools.ParseCategories(input));
    }
}

public sealed class AutostartInspectorArgumentTests
{
    private static AutorunscInspector Inspector(StubExternalToolRunner runner, bool elevated = true) =>
        new(runner, new FakeToolLocator("autorunsc.exe", "autorunsc64.exe"),
            new FakePrivilegeProbe(elevated), new WinDiagOptions());

    private static string ExpectedBuild =>
        Environment.Is64BitOperatingSystem ? "autorunsc64.exe" : "autorunsc.exe";

    private const string SampleCsv =
        "Time,Entry Location,Entry,Enabled,Category,Profile,Description,Company,Image Path,Version,Launch String\r\n" +
        "20260101-000000,HKLM\\Run,thing,enabled,Logon,System-wide,,Acme,C:\\a.exe,1.0,C:\\a.exe\r\n";

    [Fact]
    public async Task Always_asks_for_csv_and_normalised_timestamps()
    {
        var runner = new StubExternalToolRunner(SampleCsv);

        await Inspector(runner).AuditAsync(new AutostartQuery(), CancellationToken.None);

        var (executable, argv) = Assert.Single(runner.Invocations);

        Assert.Equal(ExpectedBuild, executable);
        Assert.Equal(["-accepteula", "-nobanner", "-c", "-t", "-a", "*", "*"], argv);
    }

    [Fact]
    public async Task Asks_for_every_user_profile_not_only_the_account_it_runs_as()
    {
        // Without autorunsc's trailing [user] argument it scans only its own account. Under the normal
        // deployment, a LocalSystem service, that meant SYSTEM's HKCU Run keys and Startup folder and
        // no real user's -- the commonest persistence there is, absent from a list the summary called
        // complete because the server was elevated. A category other than '*' is asked for here so the
        // trailing '*' cannot be mistaken for the category list.
        var runner = new StubExternalToolRunner(SampleCsv);

        await Inspector(runner).AuditAsync(
            new AutostartQuery(Categories: "l", VerifySignatures: true, HideMicrosoft: true, UnsignedOnly: true),
            CancellationToken.None);

        var (_, argv) = Assert.Single(runner.Invocations);

        // Last, after every switch, because autorunsc reads it positionally.
        Assert.Equal(AutorunscInspector.AllUserProfiles, argv[^1]);
        Assert.Equal("*", argv[^1]);
        Assert.Equal(1, argv.Count(a => a == "*"));
    }

    [Fact]
    public async Task Adds_the_signature_flag_only_when_something_needs_it()
    {
        var runner = new StubExternalToolRunner(SampleCsv);

        await Inspector(runner).AuditAsync(
            new AutostartQuery(Categories: "l", UnsignedOnly: true), CancellationToken.None);

        var (_, argv) = Assert.Single(runner.Invocations);

        // -u without -s means "unknown to VirusTotal" rather than "unsigned", which is a different
        // question and one this server never asks.
        Assert.Equal(["-accepteula", "-nobanner", "-c", "-t", "-a", "l", "-s", "-u", "*"], argv);
    }

    [Fact]
    public async Task Hiding_microsoft_entries_implies_verifying_them()
    {
        var runner = new StubExternalToolRunner(SampleCsv);

        await Inspector(runner).AuditAsync(
            new AutostartQuery(HideMicrosoft: true), CancellationToken.None);

        var (_, argv) = Assert.Single(runner.Invocations);

        // -m alone hides entries whose company string merely says Microsoft, which anything can claim.
        Assert.Contains("-s", argv);
        Assert.Contains("-m", argv);
    }

    [Fact]
    public async Task Never_puts_caller_text_in_the_argument_vector()
    {
        // autorunsc has no name-filter switch, so filtering happens after parsing. That turns the
        // injection question into a non-question: assert it stays that way.
        var runner = new StubExternalToolRunner(SampleCsv);

        await Inspector(runner).AuditAsync(
            new AutostartQuery(NameFilter: "-m"), CancellationToken.None);

        var (_, argv) = Assert.Single(runner.Invocations);

        Assert.DoesNotContain("-m", argv);
    }

    [Fact]
    public async Task Filters_after_parsing_across_the_fields_someone_might_know()
    {
        var runner = new StubExternalToolRunner(SampleCsv);

        var matched = await Inspector(runner).AuditAsync(
            new AutostartQuery(NameFilter: "acme"), CancellationToken.None);
        var missed = await Inspector(new StubExternalToolRunner(SampleCsv)).AuditAsync(
            new AutostartQuery(NameFilter: "nothing-like-this"), CancellationToken.None);

        Assert.Single(matched.Entries);
        Assert.Empty(missed.Entries);
    }

    [Fact]
    public async Task Carries_the_count_of_rows_it_could_not_read_past_the_name_filter()
    {
        // A record broken by a line break has no trustworthy name, and the entry it hid may be exactly
        // the one the filter is looking for -- so the count is not narrowed by the filter.
        var broken = SampleCsv + "20260101-000000,HKCU\\Run,\r\n";

        var result = await Inspector(new StubExternalToolRunner(broken)).AuditAsync(
            new AutostartQuery(NameFilter: "nothing-like-this"), CancellationToken.None);

        Assert.Empty(result.Entries);
        Assert.Equal(1, result.MalformedRowCount);
    }

    [Fact]
    public async Task Carries_the_elevation_state_so_an_empty_result_can_be_qualified()
    {
        var result = await Inspector(new StubExternalToolRunner(SampleCsv), elevated: false)
            .AuditAsync(new AutostartQuery(), CancellationToken.None);

        Assert.False(result.Elevated);
    }
}

public sealed class AutostartRenderingTests
{
    private static AutostartEntry Entry(
        string name, string? verdict = null, string? company = null, bool enabled = true) =>
        new("Logon", @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", name, enabled,
            "System-wide", null, company, $@"C:\Program Files\{name}.exe", "1.0", null, verdict, null);

    private static AutostartAuditResult Result(
        IReadOnlyList<AutostartEntry> entries,
        bool elevated = true,
        bool verified = false,
        int unsigned = 0,
        bool truncated = false) =>
        new(entries, entries.Count, truncated, elevated, verified, unsigned,
            entries.Count(e => e.ImageMissing));

    [Fact]
    public void Leads_with_the_partial_results_warning_when_unelevated()
    {
        // Same reason path_handle_search does: entries under other profiles are simply absent, and
        // absence reads as "not configured".
        var summary = AutostartTools.Render(Result([Entry("a")], elevated: false), "all", null);

        Assert.StartsWith("WARNING", summary);
        Assert.Contains("does not mean it is not configured", summary);
    }

    [Fact]
    public void Marks_the_unsigned_entries_and_counts_them()
    {
        var summary = AutostartTools.Render(
            Result([Entry("evil", "Not verified")], verified: true, unsigned: 1), "logon", null);

        Assert.Contains("[UNSIGNED]", summary);
        Assert.Contains("1 entry is not validly signed", summary);
    }

    [Fact]
    public void Says_signatures_were_not_checked_rather_than_implying_they_passed()
    {
        var summary = AutostartTools.Render(Result([Entry("a")]), "all", null);

        Assert.Contains("Signatures were not checked", summary);
        Assert.DoesNotContain("validly signed", summary);
    }

    [Fact]
    public void Names_an_entry_whose_target_file_is_gone()
    {
        // autorunsc signals this by writing "File not found: atmfd.dll" into the image column rather
        // than leaving it empty, so before it was split out the entry rendered as though nothing were
        // wrong -- quieter than a healthy one, which is backwards. Seen for real on the target: an
        // Adobe Type Manager font-driver hook pointing at a DLL Windows removed years ago.
        var orphan = Entry("Adobe Type Manager") with { ImagePath = "atmfd.dll", ImageMissing = true };

        var summary = AutostartTools.Render(Result([orphan]), "all", null);

        Assert.Contains("[FILE NOT FOUND]", summary);
        Assert.Contains("1 entry points at a file that is not there", summary);
    }

    [Fact]
    public void Names_whose_profile_a_per_user_entry_belongs_to()
    {
        // Every profile is scanned, so two users' identical HKCU Run values render identically unless
        // the profile is shown -- and "which user" is the first question about a per-user autostart.
        var perUser = Entry("Updater") with
        {
            Location = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            Profile = @"CONTOSO\jdoe"
        };

        var summary = AutostartTools.Render(Result([perUser, Entry("Agent")]), "all", null);

        Assert.Contains(@"profile CONTOSO\jdoe", summary);
        Assert.DoesNotContain("profile System-wide", summary);
    }

    [Fact]
    public void Leads_with_rows_it_could_not_read_and_does_not_call_the_list_clean()
    {
        // A record autorunsc did not write whole -- a value name carrying a line break produces one --
        // can hide a real entry or make a smuggled one look signed. Saying "every entry is validly
        // signed" over such a list is the exact false comfort the attack is after.
        var result = Result([Entry("a", "Verified", "Contoso Ltd")], verified: true) with { MalformedRowCount = 2 };

        var summary = AutostartTools.Render(result, "all", null);

        Assert.StartsWith("WARNING", summary);
        Assert.Contains("2 rows", summary);
        Assert.DoesNotContain("Every entry returned is validly signed", summary);
    }

    [Fact]
    public void Says_nothing_about_missing_files_when_none_are_missing()
    {
        Assert.DoesNotContain("FILE NOT FOUND", AutostartTools.Render(Result([Entry("a")]), "all", null));
    }

    [Fact]
    public void Names_an_entry_with_no_image_recorded_at_all()
    {
        var orphan = Entry("stale") with { ImagePath = null };

        Assert.Contains("(no image recorded)", AutostartTools.Render(Result([orphan]), "all", null));
    }

    [Fact]
    public void Shows_that_a_disabled_entry_is_disabled()
    {
        var summary = AutostartTools.Render(Result([Entry("off", enabled: false)]), "all", null);

        Assert.Contains("(disabled)", summary);
    }

    [Fact]
    public void Reports_truncation_rather_than_letting_a_page_read_as_the_whole()
    {
        var result = new AutostartAuditResult([Entry("a")], 900, true, true, false, 0);

        var summary = AutostartTools.Render(result, "all", null);

        Assert.Contains("900", summary);
        Assert.Contains("WINDIAG_MAX_RESULTS", summary);
    }
}
