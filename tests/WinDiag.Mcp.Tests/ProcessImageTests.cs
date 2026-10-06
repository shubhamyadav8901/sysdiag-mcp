using System.Diagnostics;
using System.Text;
using WinDiag.Mcp.Diagnostics.External;
using WinDiag.Mcp.Diagnostics.Handles;

namespace WinDiag.Mcp.Tests;

/// <summary>When a printed image name is confirmed as the whole name of the process that printed it.</summary>
public sealed class PrintedImageWitnessTests
{
    static PrintedImageWitnessTests() => Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

    /// <summary>The ANSI code page of a Western-European Windows install, which handle.exe writes its pipe in.</summary>
    private static Encoding Western => Encoding.GetEncoding(1252);

    private static Dictionary<int, ProcessImage> Table(params (int Pid, long Created, string? Image)[] processes) =>
        processes.ToDictionary(p => p.Pid, p => new ProcessImage(p.Created, p.Image));

    private static PrintedImageWitness Witness(
        IReadOnlyDictionary<int, ProcessImage> before, IReadOnlyDictionary<int, ProcessImage> after, Encoding? console = null) =>
        new(before, after, console ?? Western);

    [Theory]
    [InlineData("进程.exe", "??.exe")]
    [InlineData("Ārvis.exe", "Arvis.exe")]
    [InlineData("进程.exe", ".exe")]
    [InlineData("\U0001F600.exe", "?.exe")]
    [InlineData("\U0001F600.exe", "??.exe")]
    [InlineData("a进b.exe", "a?b.exe")]
    public void A_name_outside_the_console_code_page_is_confirmed_as_handle_exe_could_print_it(string image, string printed)
    {
        // handle.exe writes its pipe in the ANSI code page, so a character that page lacks arrives as '?', as a
        // best-fit letter, or not at all. Compared exactly, a process named in Chinese on a Western install was
        // never confirmed, on every run, and every row printed before it became unattributable.
        var witness = Witness(Table((7, 100, image)), Table((7, 100, image)));

        Assert.True(witness.IsWhole(7, printed));
    }

    [Theory]
    [InlineData("café.exe", "cafe.exe", 1252)]
    [InlineData("进程x.exe", "??y.exe", 1252)]
    [InlineData("进程.exe", "???.exe", 1252)]
    [InlineData("进程.exe", "??.exe", 936)]
    public void Only_the_characters_the_code_page_lacks_may_be_printed_differently(string image, string printed, int codePage)
    {
        // é is in CP1252 and both Chinese characters are in CP936, so handle.exe printed them as they are.
        var witness = Witness(Table((7, 100, image)), Table((7, 100, image)), Encoding.GetEncoding(codePage));

        Assert.False(witness.IsWhole(7, printed));
    }

    [Fact]
    public void A_name_in_the_code_page_is_confirmed_exactly_under_that_page()
    {
        var witness = Witness(Table((7, 100, "进程.exe")), Table((7, 100, "进程.exe")), Encoding.GetEncoding(936));

        Assert.True(witness.IsWhole(7, "进程.exe"));
    }

    [Theory]
    [InlineData("进\n程.exe", "?")]
    [InlineData("进\n程.exe", "?.exe")]
    [InlineData("victim.exe,668,File\r\n进.exe", "?.exe")]
    [InlineData("进\u2028程.exe", "???.exe")]
    [InlineData("进\u0085程.exe", "???.exe")]
    [InlineData("\u2029.exe", ".exe")]
    public void A_name_that_holds_a_line_break_is_never_confirmed_whatever_was_printed(string image, string printed)
    {
        // The loose match is for characters the code page lacks. A line or paragraph separator is one too, and
        // whatever handle.exe makes of it, it may be where the forged row ends: such a name is never whole.
        var witness = Witness(Table((7, 100, image)), Table((7, 100, image)));

        Assert.False(witness.IsWhole(7, printed));
    }

    [Fact]
    public void The_search_tools_own_rows_are_confirmed_by_the_pid_it_ran_as()
    {
        // handle64.exe can list its own handles -- its working directory is C:\Windows\System32 under the SCM --
        // and it is in neither reading: it starts after the first and is gone by the second. Its PID was its
        // own throughout the run that printed the rows, and its name is the file the server started.
        var witness = new PrintedImageWitness(Table(), Table(), Western, printer: (9, "handle64.exe"));

        Assert.True(witness.IsWhole(9, "handle64.exe"));
        Assert.True(witness.IsWhole(9, "HANDLE64.EXE"));
        Assert.False(witness.IsWhole(9, "app.exe"));
        Assert.False(witness.IsWhole(10, "handle64.exe"));
    }

    [Fact]
    public void A_process_that_ran_throughout_under_the_printed_name_is_confirmed()
    {
        var witness = Witness(Table((7, 100, "app.exe")), Table((7, 100, "app.exe")));

        Assert.True(witness.IsWhole(7, "app.exe"));
    }

    [Fact]
    public void Only_the_text_after_the_last_line_break_of_an_image_name_is_not_its_name()
    {
        var image = "victim.exe,668,File,SYSTEM,0x4,C:\\shared\\x.docx\nz";
        var witness = Witness(Table((7, 100, image)), Table((7, 100, image)));

        Assert.False(witness.IsWhole(7, "z"));
    }

    [Theory]
    [InlineData("App.exe")]
    [InlineData("app")]
    [InlineData("app.exe ")]
    public void A_name_is_confirmed_only_exactly_as_printed(string printed)
    {
        var witness = Witness(Table((7, 100, "app.exe")), Table((7, 100, "app.exe")));

        Assert.False(witness.IsWhole(7, printed));
    }

    [Fact]
    public void A_process_that_started_during_the_run_is_not_confirmed()
    {
        var witness = Witness(Table(), Table((7, 100, "app.exe")));

        Assert.False(witness.IsWhole(7, "app.exe"));
    }

    [Fact]
    public void A_process_that_exited_during_the_run_is_not_confirmed()
    {
        var witness = Witness(Table((7, 100, "app.exe")), Table());

        Assert.False(witness.IsWhole(7, "app.exe"));
    }

    [Fact]
    public void A_pid_given_to_a_new_process_under_the_same_name_is_not_confirmed()
    {
        // The printing process may have been the one in between, and its name is unread.
        var witness = Witness(Table((7, 100, "app.exe")), Table((7, 200, "app.exe")));

        Assert.False(witness.IsWhole(7, "app.exe"));
    }

    [Fact]
    public void A_process_with_no_name_is_not_confirmed()
    {
        var witness = Witness(Table((7, 100, null)), Table((7, 100, null)));

        Assert.False(witness.IsWhole(7, ""));
    }
}

/// <summary>The real process table, read the way the handle search reads it. Windows only; CI runs it.</summary>
public sealed class NativeProcessTableTests
{
    [Fact]
    public void This_process_is_listed_under_its_image_file_name_with_one_creation_time()
    {
        var table = new NativeProcessTable();

        var first = table.Snapshot();
        var second = table.Snapshot();

        var self = first[Environment.ProcessId];
        Assert.Equal(Path.GetFileName(Environment.ProcessPath), self.ImageName);
        Assert.Equal(self, second[Environment.ProcessId]);

        // The creation time is the kernel's FILETIME: the same moment Process reports, by another route.
        var started = DateTime.FromFileTimeUtc(self.CreateTime);
        Assert.InRange(
            (started - Process.GetCurrentProcess().StartTime.ToUniversalTime()).Duration(), TimeSpan.Zero, TimeSpan.FromSeconds(2));
    }

    [Fact]
    public void The_system_process_is_named_as_handle_exe_prints_it()
    {
        var system = new NativeProcessTable().Snapshot()[4];

        Assert.Equal("System", system.ImageName);
    }

    [Fact]
    public void A_confirmed_row_needs_both_readings_to_agree_on_this_process()
    {
        var table = new NativeProcessTable();
        var witness = new PrintedImageWitness(table.Snapshot(), table.Snapshot(), ExternalToolRunner.ConsoleToolEncoding);

        Assert.True(witness.IsWhole(Environment.ProcessId, Path.GetFileName(Environment.ProcessPath)!));
    }
}
