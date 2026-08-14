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
        var entries = HandleCsvParser.Parse(LoadFixture("handle-u-v-fonts.csv"));

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
        var entries = HandleCsvParser.Parse(LoadFixture("handle-u-v-fonts.csv"));

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

        var entries = HandleCsvParser.Parse(csv);

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

        var entry = Assert.Single(HandleCsvParser.Parse(csv));

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

        var entry = Assert.Single(HandleCsvParser.Parse(csv));

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
        Assert.Empty(HandleCsvParser.Parse(string.Empty));
        Assert.Empty(HandleCsvParser.Parse("   \r\n  "));
    }

    [Fact]
    public void Trims_the_trailing_space_handle_exe_appends_to_names()
    {
        const string csv = """
            Process,PID,User,Handle,Type,Share Flags,Name,Access
            app.exe,42,File,CONTOSO\user,0x000000F0,C:\Windows\Fonts\arial.ttf
            """;

        Assert.Equal(@"C:\Windows\Fonts\arial.ttf", Assert.Single(HandleCsvParser.Parse(csv)).Name);
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

    private static IReadOnlyList<HandleEntry> Parsed() => HandleCsvParser.Parse(Fixture());

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
