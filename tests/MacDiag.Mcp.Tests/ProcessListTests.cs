using System.Collections;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Processes;
using MacDiag.Mcp.Mac.Parsers;
using MacDiag.Mcp.Tools;
using static MacDiag.Mcp.Tests.SystemOverviewTests;

namespace MacDiag.Mcp.Tests;

public sealed class ProcessListTests
{
    internal static FakeCommands Ps(string? args = null, string? comm = null) => new((program, arguments) =>
        program != "ps" ? new ExternalResult(1, "", "unexpected program")
        : arguments.Any(a => a.Contains("comm=", StringComparison.Ordinal)) ? FakeCommands.Ok(comm ?? Fixture(Unverified, "ps-comm"))
        : FakeCommands.Ok(args ?? Fixture(Unverified, "ps-args")));

    internal static Task<ProcessTable> Table(FakeCommands? commands = null) =>
        new MacProcessTable(commands ?? Ps(), MacDiagOptions.FromEnvironment(new Hashtable())).ReadAsync(CancellationToken.None);

    [Fact]
    public async Task Columns_parse_with_start_time_in_local_time_memory_in_bytes_and_arguments_spacing_kept()
    {
        var java = (await Table()).Processes.Single(p => p.ProcessId == 612);

        Assert.Equal(1, java.ParentProcessId);
        Assert.Equal(501, java.UserId);
        Assert.Equal(98304L * 1024, java.ResidentBytes);
        Assert.Equal(new DateTimeOffset(new DateTime(2024, 10, 1, 7, 15, 42, DateTimeKind.Local)), java.StartTime);
        Assert.Equal("/usr/bin/java -jar /Users/a b/app.jar  --port 8080", java.CommandLine);
    }

    [Fact]
    public async Task The_executable_path_is_comm_when_rooted_and_keeps_its_spaces_and_a_bare_comm_is_only_a_name()
    {
        var table = await Table();

        var code = table.Processes.Single(p => p.ProcessId == 850);
        Assert.Equal("/Applications/Visual Studio Code.app/Contents/MacOS/Electron", code.ExecutablePath);
        Assert.Equal("Electron", code.Name);

        var java = table.Processes.Single(p => p.ProcessId == 612);
        Assert.Null(java.ExecutablePath);
        Assert.Equal("java", java.Name);
    }

    [Fact]
    public async Task A_process_gone_before_the_second_call_keeps_no_path_and_one_born_after_the_first_is_not_listed()
    {
        // Review Focus 2: never pair one PID's row with another's path.
        var table = await Table();

        var gone = table.Processes.Single(p => p.ProcessId == 777);
        Assert.Null(gone.ExecutablePath);
        Assert.Equal("short-lived", gone.Name);
        Assert.DoesNotContain(table.Processes, p => p.ProcessId == 900);
    }

    [Fact]
    public async Task Vis_encoded_arguments_are_decoded_and_a_malformed_line_is_counted_not_guessed()
    {
        var table = await Table();

        Assert.Equal("/bin/sleep 30 café", table.Processes.Single(p => p.ProcessId == 640).CommandLine);
        Assert.Contains(table.Limitations, l => l.Contains("1 ps line", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_pid_comm_lists_twice_has_an_unknown_path_and_a_limitation_rather_than_a_crash()
    {
        var table = await Table(Ps(comm:
            "  501 Tue Oct  1 06:01:05 2024     /a/forged\n  501 Tue Oct  1 06:01:05 2024     /System/Library/CoreServices/Finder.app/Contents/MacOS/Finder\n"));

        Assert.Null(table.Processes.Single(p => p.ProcessId == 501).ExecutablePath);
        Assert.Contains(table.Limitations, l => l.Contains("501", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_pid_reused_between_the_two_calls_never_takes_the_other_process_path()
    {
        // Review Focus 2: PID 501 exited and a new process got its number before the comm call; the start times differ.
        var table = await Table(Ps(comm: "  501 Tue Oct  1 12:34:56 2024     /tmp/impostor\n"));

        Assert.Null(table.Processes.Single(p => p.ProcessId == 501).ExecutablePath);
    }

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("café", "café")] // ps under a UTF-8 LC_CTYPE prints valid UTF-8 as itself
    [InlineData("a\\011b", "a\tb")]
    [InlineData("a\\012b", "a\nb")]
    // A backslash in a real command line is printed as-is, so these are text, not escapes.
    [InlineData("-Dre=\\d+\\s", "-Dre=\\d+\\s")]
    [InlineData("C:\\new\\040x", "C:\\new\\040x")]
    [InlineData("a\\\\b", "a\\\\b")]
    // ^x and M-x carry no backslash, so they are indistinguishable from text like this and are left as printed.
    [InlineData("grep ^[a-z] ^A", "grep ^[a-z] ^A")]
    [InlineData("cafM-CM-) M^@", "cafM-CM-) M^@")]
    public void Only_the_tab_and_newline_escapes_are_decoded_and_everything_else_is_kept_as_ps_printed_it(string printed, string decoded)
    {
        Assert.Equal(decoded, VisDecode.Decode(printed));
    }

    [Fact]
    public async Task The_tool_filters_by_name_or_command_line_orders_by_name_and_caps_with_the_count_kept()
    {
        var table = await Table();

        var filtered = ProcessTools.Build(table, nameFilter: "JAR", processId: null, maxResults: 50);
        Assert.Equal([612], filtered.Processes.Select(p => p.ProcessId));

        var all = ProcessTools.Build(table, nameFilter: null, processId: null, maxResults: 2);
        Assert.Equal(2, all.Processes.Count);
        Assert.True(all.Truncated);
        Assert.Equal(6, all.TotalMatched);
        Assert.Equal(["Electron", "Finder"], all.Processes.Select(p => p.Name));

        var launchd = ProcessTools.Build(table, nameFilter: null, processId: 1, maxResults: 50).Processes.Single();
        Assert.Null(launchd.ParentProcessId);
    }

    [Fact]
    public async Task A_failing_ps_reaches_the_caller_with_its_message()
    {
        var failing = new FakeCommands((_, _) => new ExternalResult(1, "", "ps: boom"));

        var ex = await Assert.ThrowsAsync<ProcessQueryException>(() => Table(failing));

        Assert.Contains("ps: boom", ex.Message, StringComparison.Ordinal);
    }
}
