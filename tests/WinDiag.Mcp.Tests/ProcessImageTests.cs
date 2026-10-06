using System.Diagnostics;
using WinDiag.Mcp.Diagnostics.Handles;

namespace WinDiag.Mcp.Tests;

/// <summary>When a printed image name is confirmed as the whole name of the process that printed it.</summary>
public sealed class PrintedImageWitnessTests
{
    private static Dictionary<int, ProcessImage> Table(params (int Pid, long Created, string? Image)[] processes) =>
        processes.ToDictionary(p => p.Pid, p => new ProcessImage(p.Created, p.Image));

    [Fact]
    public void A_process_that_ran_throughout_under_the_printed_name_is_confirmed()
    {
        var witness = new PrintedImageWitness(Table((7, 100, "app.exe")), Table((7, 100, "app.exe")));

        Assert.True(witness.IsWhole(7, "app.exe"));
    }

    [Fact]
    public void Only_the_text_after_the_last_line_break_of_an_image_name_is_not_its_name()
    {
        var image = "victim.exe,668,File,SYSTEM,0x4,C:\\shared\\x.docx\nz";
        var witness = new PrintedImageWitness(Table((7, 100, image)), Table((7, 100, image)));

        Assert.False(witness.IsWhole(7, "z"));
    }

    [Theory]
    [InlineData("App.exe")]
    [InlineData("app")]
    [InlineData("app.exe ")]
    public void A_name_is_confirmed_only_exactly_as_printed(string printed)
    {
        var witness = new PrintedImageWitness(Table((7, 100, "app.exe")), Table((7, 100, "app.exe")));

        Assert.False(witness.IsWhole(7, printed));
    }

    [Fact]
    public void A_process_that_started_during_the_run_is_not_confirmed()
    {
        var witness = new PrintedImageWitness(Table(), Table((7, 100, "app.exe")));

        Assert.False(witness.IsWhole(7, "app.exe"));
    }

    [Fact]
    public void A_process_that_exited_during_the_run_is_not_confirmed()
    {
        var witness = new PrintedImageWitness(Table((7, 100, "app.exe")), Table());

        Assert.False(witness.IsWhole(7, "app.exe"));
    }

    [Fact]
    public void A_pid_given_to_a_new_process_under_the_same_name_is_not_confirmed()
    {
        // The printing process may have been the one in between, and its name is unread.
        var witness = new PrintedImageWitness(Table((7, 100, "app.exe")), Table((7, 200, "app.exe")));

        Assert.False(witness.IsWhole(7, "app.exe"));
    }

    [Fact]
    public void A_process_with_no_name_is_not_confirmed()
    {
        var witness = new PrintedImageWitness(Table((7, 100, null)), Table((7, 100, null)));

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
        var witness = new PrintedImageWitness(table.Snapshot(), table.Snapshot());

        Assert.True(witness.IsWhole(Environment.ProcessId, Path.GetFileName(Environment.ProcessPath)!));
    }
}
