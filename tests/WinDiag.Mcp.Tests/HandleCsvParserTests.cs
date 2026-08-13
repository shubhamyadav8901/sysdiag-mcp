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
    public void Refuses_the_process_scoped_layout_instead_of_mis_attributing_every_field()
    {
        // handle.exe -p emits a 7-column header with no Access, above 7-field rows that DO follow
        // header order. Those rows have enough fields to satisfy the positional parser, so without an
        // explicit layout check this would parse "cleanly" and put the user name in Type, the handle
        // in User, and so on -- wrong data with no error. Nothing passes -p today; this is the
        // tripwire for the day someone adds it.
        const string csv = """
            Process,PID,User,Handle,Type,Share Flags,Name
            explorer.exe,3628,CONTOSO\user,0x00000054,File,,C:\Windows\System32
            """;

        var ex = Assert.Throws<FormatException>(() => HandleCsvParser.Parse(csv));

        Assert.Contains("layout", ex.Message);
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
        var fields = HandleCsvParser.SplitCsvLine("a,\"b,c\",\"say \"\"hi\"\"\",d");

        Assert.Equal(["a", "b,c", "say \"hi\"", "d"], fields);
    }
}
