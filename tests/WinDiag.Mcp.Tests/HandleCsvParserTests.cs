using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.Handles;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// Guards the positional parsing of handle.exe CSV.
/// </summary>
/// <remarks>
/// These assertions exist because handle.exe's header lies about its own rows. If someone later
/// "fixes" the parser to map by header name, every one of these fails -- which is the point.
/// </remarks>
public sealed class HandleCsvParserTests
{
    private static string LoadFixture(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    [Fact]
    public void Parses_captured_output_positionally_not_by_header_name()
    {
        var entries = HandleCsvParser.Parse(LoadFixture("handle-u-v-fonts.csv")).Entries;

        Assert.Equal(7, entries.Count);

        var first = entries[0];
        Assert.Equal("explorer.exe", first.ProcessName);
        Assert.Equal(3628, first.ProcessId);

        // The header claims field 2 is "User" and field 4 is "Type". It is the other way round.
        // Mapping by header name would put "File" in User and the account name in Handle.
        Assert.Equal("File", first.Type);
        Assert.Equal(@"CONTOSO\jdoe", first.User);
        Assert.Equal("0x0000068C", first.HandleValue);
        Assert.Equal(@"C:\Windows\Fonts\StaticCache.dat", first.Name);
    }

    [Fact]
    public void Skips_the_header_row_without_treating_it_as_data()
    {
        var entries = HandleCsvParser.Parse(LoadFixture("handle-u-v-fonts.csv")).Entries;

        Assert.DoesNotContain(entries, e => e.ProcessName == "Process");
    }

    [Fact]
    public void Skips_access_denied_diagnostics_interleaved_with_rows()
    {
        // handle.exe writes these to stdout, mixed into the data, when it is not elevated. Failing the
        // whole call on them would throw away the partial result that is still useful.
        const string csv = """
            Process,PID,User,Handle,Type,Share Flags,Name,Access
            Error obtaining handle information: Access denied
            explorer.exe,3628,File,CONTOSO\user,0x0000068C,C:\Windows\Fonts\StaticCache.dat
            """;

        var entries = HandleCsvParser.Parse(csv).Entries;

        var entry = Assert.Single(entries);
        Assert.Equal("explorer.exe", entry.ProcessName);
    }

    [Fact]
    public void Keeps_commas_that_belong_to_the_path()
    {
        // handle.exe does not quote paths, so a comma in a folder name would otherwise split the name
        // and silently truncate it at the comma.
        const string csv = """
            Process,PID,User,Handle,Type,Share Flags,Name,Access
            app.exe,42,File,CONTOSO\user,0x000000F0,C:\Data\Reports, Q3\summary.docx
            """;

        var entry = Assert.Single(HandleCsvParser.Parse(csv).Entries);

        Assert.Equal(@"C:\Data\Reports, Q3\summary.docx", entry.Name);
    }

    [Fact]
    public void Reads_the_process_scoped_layout_by_its_own_column_order()
    {
        // handle.exe -p emits a 7-column header with no Access, above 7-field rows that DO follow
        // header order -- the opposite of the name search above. Those rows have enough fields to
        // satisfy the positional parser, so before the layout check existed this parsed "cleanly" and
        // put the user name in Type and the handle in User: wrong data, no error.
        //
        // This test was originally written as a tripwire asserting a refusal, for "the day someone
        // adds -p". That day came with process_handles, and the refusal fired exactly as intended --
        // which is how the second layout was discovered rather than shipped.
        const string csv = """
            Process,PID,User,Handle,Type,Share Flags,Name
            explorer.exe,3628,CONTOSO\user,0x00000054,File,,C:\Windows\System32
            """;

        var entry = Assert.Single(HandleCsvParser.Parse(csv).Entries);

        Assert.Equal("explorer.exe", entry.ProcessName);
        Assert.Equal(3628, entry.ProcessId);
        Assert.Equal("File", entry.Type);
        Assert.Equal(@"CONTOSO\user", entry.User);
        Assert.Equal("0x00000054", entry.HandleValue);
        Assert.Equal(@"C:\Windows\System32", entry.Name);
    }

    [Fact]
    public void Returns_nothing_for_empty_output()
    {
        Assert.Empty(HandleCsvParser.Parse(string.Empty).Entries);
        Assert.Empty(HandleCsvParser.Parse("   \r\n  ").Entries);
    }

    [Fact]
    public void Trims_the_trailing_space_handle_exe_appends_to_names()
    {
        const string csv = """
            Process,PID,User,Handle,Type,Share Flags,Name,Access
            app.exe,42,File,CONTOSO\user,0x000000F0,C:\Windows\Fonts\arial.ttf
            """;

        Assert.Equal(@"C:\Windows\Fonts\arial.ttf", Assert.Single(HandleCsvParser.Parse(csv).Entries).Name);
    }

    [Fact]
    public void Finds_no_unattributable_rows_in_either_real_capture()
    {
        // The count below must mean something when it is not zero, so it must be zero on real output.
        Assert.Equal(0, HandleCsvParser.Parse(LoadFixture("handle-u-v-fonts.csv")).UnparsedRows);
        Assert.Equal(0, HandleCsvParser.Parse(LoadFixture("handle-p-explorer.csv"), processId: 14032).UnparsedRows);
    }

    [Fact]
    public void Keeps_a_comma_in_the_process_image_name_out_of_the_pid_column()
    {
        // Commas are legal in NTFS names, so in image names, and handle.exe quotes nothing. Read by
        // fixed position, `a,b.exe` put "b.exe" in the PID column, the row failed to parse and was
        // skipped -- and an elevated search then said "No open file references matched", the confident
        // negative this tool exists to never give.
        const string csv = """
            Process,PID,User,Handle,Type,Share Flags,Name,Access
            a,b.exe,1234,File,CONTOSO\jdoe,0x00000460,C:\shared\x.docx
            """;

        var parsed = HandleCsvParser.Parse(csv);

        var entry = Assert.Single(parsed.Entries);
        Assert.Equal("a,b.exe", entry.ProcessName);
        Assert.Equal(1234, entry.ProcessId);
        Assert.Equal("File", entry.Type);
        Assert.Equal(@"CONTOSO\jdoe", entry.User);
        Assert.Equal("0x00000460", entry.HandleValue);
        Assert.Equal(@"C:\shared\x.docx", entry.Name);
        Assert.Equal(0, parsed.UnparsedRows);
    }

    [Fact]
    public void Never_blames_a_pid_spelled_out_inside_a_process_image_name()
    {
        // A binary named `x,668,File,SYSTEM,0x4,svc.exe` -- no character Windows forbids -- read by
        // fixed position came out as process x, PID 668, user SYSTEM, with the real PID buried in the
        // name. The lock was pinned on whichever victim the name chose, and the next step a caller
        // takes on a holder is process_control or capture_dump. Two readings fit this row, and nothing
        // in it can settle which is real -- the forged reading's name always contains the real one, so
        // even the search term matches both. Neither is picked; the row is reported as unreadable.
        const string csv = """
            Process,PID,User,Handle,Type,Share Flags,Name,Access
            x,668,File,SYSTEM,0x4,svc.exe,1234,File,CONTOSO\jdoe,0x00000460,C:\shared\x.docx
            """;

        var parsed = HandleCsvParser.Parse(csv);

        Assert.DoesNotContain(parsed.Entries, e => e.ProcessId == 668);
        Assert.Empty(parsed.Entries);
        Assert.Equal(1, parsed.UnparsedRows);
    }

    [Fact]
    public void Anchors_a_process_scoped_row_on_the_pid_that_was_asked_for()
    {
        // In -p mode the PID is known before handle.exe runs, so it is the anchor: a PID spelled out
        // in the image name cannot be taken for it, and a comma in the name cannot shift the columns.
        const string csv = """
            Process,PID,User,Handle,Type,Share Flags,Name
            x,668,SYSTEM,0x4,Key,,y.exe,1234,CONTOSO\jdoe,0x0000000C,Key,,HKLM\SOFTWARE\Contoso
            """;

        var parsed = HandleCsvParser.Parse(csv, processId: 1234);

        var entry = Assert.Single(parsed.Entries);
        Assert.Equal(1234, entry.ProcessId);
        Assert.Equal("x,668,SYSTEM,0x4,Key,,y.exe", entry.ProcessName);
        Assert.Equal(@"CONTOSO\jdoe", entry.User);
        Assert.Equal("Key", entry.Type);
        Assert.Equal(@"HKLM\SOFTWARE\Contoso", entry.Name);
    }

    [Fact]
    public void Counts_a_long_enough_row_it_cannot_read_instead_of_skipping_it()
    {
        const string csv = """
            Process,PID,User,Handle,Type,Share Flags,Name,Access
            app.exe,not-a-pid,File,CONTOSO\jdoe,0x00000460,C:\x
            Error obtaining handle information: Access denied
            """;

        var parsed = HandleCsvParser.Parse(csv);

        Assert.Empty(parsed.Entries);

        // The diagnostic line is too short to be a row and is still skipped; the malformed row is not.
        Assert.Equal(1, parsed.UnparsedRows);
    }

    [Fact]
    public void Splits_quoted_fields_and_doubled_quote_escapes()
    {
        var fields = DelimitedLine.Split("a,\"b,c\",\"say \"\"hi\"\"\",d");

        Assert.Equal(["a", "b,c", "say \"hi\"", "d"], fields);
    }
}

/// <summary>
/// The second layout handle.exe emits, and the reason the parser cannot pick one rule and keep it.
/// </summary>
/// <remarks>
/// Captured from <c>handle64 -a -p &lt;pid&gt; -u -v</c> against Explorer on Windows 11, Handle 5.0.
/// Unlike the name-search layout, this header DOES describe its rows -- so applying the name-search
/// indices here places the user name in Type and the handle value in User, on rows long enough to pass
/// any "enough fields" check. That is how this layout was found: the guard refused it rather than
/// answering wrongly.
/// </remarks>
public sealed class ProcessScopedHandleLayoutTests
{
    private static string Fixture() =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "handle-p-explorer.csv"));

    private static IReadOnlyList<HandleEntry> Parsed() => HandleCsvParser.Parse(Fixture(), processId: 14032).Entries;

    [Fact]
    public void Reads_the_process_scoped_layout()
    {
        var entries = Parsed();

        Assert.NotEmpty(entries);
        Assert.All(entries, e => Assert.Equal("explorer.exe", e.ProcessName));
        Assert.All(entries, e => Assert.Equal(14032, e.ProcessId));
    }

    [Fact]
    public void Attributes_every_field_to_the_column_it_belongs_to()
    {
        // The whole point. Under the name-search indices these three would be Type="CONTOSO\testuser",
        // User="0x0000000C" and Handle="Key" -- all plausible-looking, none correct.
        var key = Parsed().Single(e => e.Type == "Key");

        Assert.Equal(@"CONTOSO\testuser", key.User);
        Assert.Equal("0x0000000C", key.HandleValue);
        Assert.StartsWith(@"HKLM\SOFTWARE\Microsoft", key.Name);
    }

    [Fact]
    public void Covers_the_object_types_that_justify_scoping_to_one_process()
    {
        // Mutants, sections and tokens are most of the reason to ask about a single process, and none
        // of them appears in a file-only name search.
        var types = Parsed().Select(e => e.Type).ToHashSet(StringComparer.Ordinal);

        Assert.Contains("Mutant", types);
        Assert.Contains("Section", types);
        Assert.Contains("Token", types);
        Assert.Contains("Key", types);
    }

    [Fact]
    public void Keeps_an_unnamed_object_rather_than_dropping_it()
    {
        // An Event with no name is still a handle the process holds, and dropping it would make the
        // count wrong.
        Assert.Contains(Parsed(), e => e.Type == "Event" && string.IsNullOrEmpty(e.Name));
    }

    [Fact]
    public void Still_refuses_a_layout_that_is_neither_of_the_two_known_ones()
    {
        var unknown = "Process,PID,Something,Else" + Environment.NewLine + "explorer.exe,1,a,b";

        var ex = Assert.Throws<FormatException>(() => HandleCsvParser.Parse(unknown));

        Assert.Contains("Two layouts are known", ex.Message);
    }
}

/// <summary>A line break inside an object name must not be able to start a row of its own.</summary>
/// <remarks>
/// <para>handle.exe ends each row with a line break and quotes nothing, and the name of an event, a
/// mutant, a section, a pipe or a registry key may itself hold a CR or an LF: the native APIs take any
/// character but a backslash in a leaf name, and an unprivileged user names their own objects. Read line
/// by line, the text after the break became a row of its own -- <c>victim.exe,668,File,...,C:\shared\x.docx</c>
/// -- with exactly one fit, so it was accepted and PID 668 was reported holding a file it never opened.
/// Whatever handle.exe writes for a record end, a name can contain the same characters, so no line can be
/// proven to start a record once a name that can hold a break has been printed.</para>
/// <para>The rule pinned here: a name that cannot hold a line break -- none, or a path on a drive letter,
/// whose file systems forbid control characters -- leaves the next line provably a row. After any other
/// name, a line is attributed only to the process holding that object, and marked unproven; a line
/// claiming any other process is counted as unattributable, never listed.</para>
/// </remarks>
public sealed class HandleLineBreakTests
{
    private const string NameSearchHeader = "Process,PID,User,Handle,Type,Share Flags,Name,Access";
    private const string ProcessHeader = "Process,PID,User,Handle,Type,Share Flags,Name";

    // How the -p capture ends a row: a space, then CRLF. The name-search capture ends with a bare LF;
    // either way, a name can hold the same characters, which is the point of these tests.
    private const string RowEnd = " \r\n";

    public static TheoryData<string> LineBreaks => new() { "\n", "\r", "\r\n" };

    [Theory]
    [MemberData(nameof(LineBreaks))]
    public void A_line_break_in_an_object_name_cannot_blame_another_pid_in_a_name_search(string lineBreak)
    {
        // evil.exe holds an event named "...\x.docx<break>victim.exe,668,File,..." -- the search term
        // matches the full name, so handle.exe prints it, and the text after the break reads as a row.
        var csv = NameSearchHeader + "\r\n" +
                  @"evil.exe,4242,Event,CONTOSO\mallory,0x00000010,\Sessions\1\BaseNamedObjects\x.docx" + lineBreak +
                  @"victim.exe,668,File,NT AUTHORITY\SYSTEM,0x00000004,C:\shared\x.docx" + RowEnd +
                  @"word.exe,5150,File,CONTOSO\jdoe,0x00000460,C:\shared\x.docx" + RowEnd;

        var parsed = HandleCsvParser.Parse(csv);

        Assert.DoesNotContain(parsed.Entries, e => e.ProcessId == 668);
        var evil = Assert.Single(parsed.Entries);
        Assert.Equal(4242, evil.ProcessId);
        Assert.False(evil.Unproven);

        // word.exe's row is real, but nothing tells it from more of the event's name: it is counted, so the
        // result is never read as complete -- not listed, and not silently dropped.
        Assert.Equal(2, parsed.UnparsedRows);
    }

    [Fact]
    public void A_forged_row_with_a_drive_path_does_not_vouch_for_the_line_after_it()
    {
        // The first forged line ends in a drive path, a name that cannot hold a break -- but it is itself
        // text from the event's name, which carries on to a second forged line.
        var csv = NameSearchHeader + "\r\n" +
                  @"evil.exe,4242,Event,CONTOSO\mallory,0x00000010,\BaseNamedObjects\x.docx" + "\n" +
                  @"svc.exe,700,File,NT AUTHORITY\SYSTEM,0x00000004,C:\decoy.txt" + "\n" +
                  @"victim.exe,668,File,NT AUTHORITY\SYSTEM,0x00000008,C:\shared\x.docx" + RowEnd;

        var parsed = HandleCsvParser.Parse(csv);

        Assert.DoesNotContain(parsed.Entries, e => e.ProcessId is 668 or 700);
        Assert.Equal(2, parsed.UnparsedRows);
    }

    [Fact]
    public void A_line_after_a_breakable_name_that_claims_the_same_process_is_listed_but_unproven()
    {
        // Whatever it is, it can only be attributed to the process that holds the object whose name it
        // may come from -- the residual this rule accepts, and says so.
        var csv = NameSearchHeader + "\r\n" +
                  @"evil.exe,4242,Event,CONTOSO\mallory,0x00000010,\BaseNamedObjects\x.docx" + RowEnd +
                  @"evil.exe,4242,File,CONTOSO\mallory,0x00000014,C:\shared\x.docx" + RowEnd;

        var parsed = HandleCsvParser.Parse(csv);

        Assert.Equal(2, parsed.Entries.Count);
        Assert.False(parsed.Entries[0].Unproven);
        Assert.True(parsed.Entries[1].Unproven);
        Assert.Equal(0, parsed.UnparsedRows);
    }

    [Fact]
    public void A_line_after_a_breakable_name_that_claims_the_right_pid_under_another_image_is_not_listed()
    {
        // The PID matches the object's holder, but the image name is made up: listing it would show
        // "victim.exe (PID 4242)" -- a process that does not exist, named by whoever named the event.
        var csv = NameSearchHeader + "\r\n" +
                  @"evil.exe,4242,Event,CONTOSO\mallory,0x00000010,\BaseNamedObjects\x.docx" + "\n" +
                  @"victim.exe,4242,File,NT AUTHORITY\SYSTEM,0x00000014,C:\shared\x.docx" + RowEnd;

        var parsed = HandleCsvParser.Parse(csv);

        Assert.DoesNotContain(parsed.Entries, e => e.ProcessName == "victim.exe");
        Assert.Equal(1, parsed.UnparsedRows);
    }

    [Fact]
    public void A_search_whose_names_are_all_drive_paths_is_proven_throughout()
    {
        // The default path_handle_search: file handles to paths on drive letters, none of which can hold
        // a line break. The rule must cost this case nothing.
        var parsed = HandleCsvParser.Parse(File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "Fixtures", "handle-u-v-fonts.csv")));

        Assert.Equal(7, parsed.Entries.Count);
        Assert.All(parsed.Entries, e => Assert.False(e.Unproven));
        Assert.Equal(0, parsed.UnparsedRows);
    }

    [Fact]
    public void An_unreadable_row_leaves_every_later_row_unattributable_in_a_name_search()
    {
        // Its name could not be told from its image name, so whether it holds a break cannot be either.
        var csv = NameSearchHeader + "\r\n" +
                  @"x,668,File,SYSTEM,0x4,svc.exe,1234,File,CONTOSO\jdoe,0x00000460,\BaseNamedObjects\x.docx" + "\n" +
                  @"victim.exe,669,File,NT AUTHORITY\SYSTEM,0x00000004,C:\shared\x.docx" + RowEnd;

        var parsed = HandleCsvParser.Parse(csv);

        Assert.Empty(parsed.Entries);
        Assert.Equal(2, parsed.UnparsedRows);
    }

    [Theory]
    [MemberData(nameof(LineBreaks))]
    public void A_line_break_in_an_object_name_in_process_scope_is_held_to_the_scoped_pid_and_marked(string lineBreak)
    {
        // Under -p every row must carry the PID asked for, so a forged line naming another process is not
        // attributed at all; one naming the scoped process is listed, marked unproven.
        var csv = ProcessHeader + "\r\n" +
                  @"svc.exe,1234,NT AUTHORITY\SYSTEM,0x00000004,File,,C:\Windows\System32" + RowEnd +
                  @"svc.exe,1234,NT AUTHORITY\SYSTEM,0x0000000C,Key,,HKCU\Software\Contoso" + lineBreak +
                  @"victim.exe,668,NT AUTHORITY\SYSTEM,0x00000004,File,,C:\shared\x.docx" + lineBreak +
                  @"svc.exe,1234,NT AUTHORITY\SYSTEM,0x00000010,File,,C:\shared\x.docx" + RowEnd;

        var parsed = HandleCsvParser.Parse(csv, processId: 1234);

        Assert.DoesNotContain(parsed.Entries, e => e.ProcessId == 668);
        Assert.Equal(3, parsed.Entries.Count);
        Assert.False(parsed.Entries[0].Unproven);
        Assert.False(parsed.Entries[1].Unproven);
        Assert.True(parsed.Entries[2].Unproven);
        Assert.Equal(@"C:\shared\x.docx", parsed.Entries[2].Name);
        Assert.Equal(1, parsed.UnparsedRows);
    }

    [Fact]
    public void The_captured_process_scope_marks_every_row_after_its_first_named_registry_key()
    {
        // The real capture opens on a Key, whose name can hold a break: from there on nothing is proven.
        var parsed = HandleCsvParser.Parse(File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "Fixtures", "handle-p-explorer.csv")), processId: 14032);

        Assert.Equal(7, parsed.Entries.Count);
        Assert.False(parsed.Entries[0].Unproven);
        Assert.All(parsed.Entries.Skip(1), e => Assert.True(e.Unproven));
    }
}
