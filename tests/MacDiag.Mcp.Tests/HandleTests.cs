using System.Collections;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Handles;
using MacDiag.Mcp.Mac.Parsers;
using static MacDiag.Mcp.Tests.LsofTests;

namespace MacDiag.Mcp.Tests;

public sealed class HandleTests
{
    internal sealed class Privileges(bool elevated) : IPrivilegeProbe
    {
        public bool IsElevated => elevated;
    }

    /// <summary>lsof answers from a fixture (or not at all); ps -p says whether the PID exists.</summary>
    internal static FakeCommands Commands(string? lsof, bool processExists = true) => new((program, arguments) => program switch
    {
        "lsof" => lsof is null ? new ExternalResult(1, "", "") : FakeCommands.Ok(lsof),
        "ps" => processExists ? FakeCommands.Ok("  501\n") : new ExternalResult(1, "", ""),
        _ => new ExternalResult(1, "", "unexpected program"),
    });

    private static MacDiagOptions Options() => MacDiagOptions.FromEnvironment(new Hashtable());

    private static MacHandleInspector Handles(FakeCommands commands, bool elevated = true) =>
        new(commands, new Privileges(elevated), Options());

    [Theory]
    [InlineData("txt", "REG", "Mapped")]
    [InlineData("cwd", "DIR", "Directory")]
    [InlineData("3", "REG", "File")]
    [InlineData("3", "DIR", "Directory")]
    [InlineData("3", "CHR", "Device")]
    [InlineData("3", "IPv4", "Socket")]
    [InlineData("3", "IPv6", "Socket")]
    [InlineData("3", "unix", "UnixSocket")]
    [InlineData("3", "FIFO", "Fifo")]
    [InlineData("3", "PIPE", "Pipe")]
    [InlineData("3", "KQUEUE", "Kqueue")]
    [InlineData("3", "NPOLICY", "NPOLICY")]
    public void Lsof_types_map_to_handle_kinds(string descriptor, string type, string kind)
    {
        Assert.Equal(kind, HandleKind.Of(new LsofFile(descriptor, null, type, null, null, null, null, "x", null, null)));
    }

    [Fact]
    public async Task Every_open_object_of_one_process_is_listed_with_how_it_was_opened()
    {
        var result = await Handles(Commands(RawFixture("lsof-p"))).ForProcessAsync(501, includeAllObjectTypes: true, CancellationToken.None);

        Assert.Equal("PID 501", result.Query);
        Assert.True(result.ProcessScoped);
        Assert.Equal(7, result.Entries.Count);
        Assert.Contains(result.Entries, e => e.HandleValue == "3" && e.Type == "File" && e.Access == "read" && e.Name == "/Users/a/café\tnotes.txt");
        Assert.Contains(result.Entries, e => e.HandleValue == "6" && e.Type == "Fifo" && e.Access == "read-write");
        Assert.All(result.Entries, e => Assert.Equal(("Finder", 501), (e.ProcessName, e.ProcessId)));
    }

    [Fact]
    public async Task File_references_only_keeps_files_directories_and_mapped_files()
    {
        var result = await Handles(Commands(RawFixture("lsof-p"))).ForProcessAsync(501, includeAllObjectTypes: false, CancellationToken.None);

        Assert.Equal(["Directory", "File", "Mapped"], result.Entries.Select(e => e.Type).Distinct().Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task A_process_that_is_not_running_is_named_as_such()
    {
        var ex = await Assert.ThrowsAsync<HandleQueryException>(() =>
            Handles(Commands(lsof: null, processExists: false)).ForProcessAsync(4242, true, CancellationToken.None));

        Assert.Contains("No process with PID 4242 is running", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_running_process_lsof_cannot_read_is_not_called_gone()
    {
        // lsof prints nothing for another user's process when the server is not root, exactly as for a missing PID.
        var ex = await Assert.ThrowsAsync<HandleQueryException>(() =>
            Handles(Commands(lsof: null, processExists: true), elevated: false).ForProcessAsync(501, true, CancellationToken.None));

        Assert.Contains("is running but its open files are not readable without root", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_pid_of_zero_or_less_is_refused_before_anything_runs()
    {
        var commands = Commands(RawFixture("lsof-p"));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => Handles(commands).ForProcessAsync(0, true, CancellationToken.None));
        Assert.Empty(commands.Calls);
    }

    [Fact]
    public async Task Modules_are_the_mapped_files_and_always_say_the_shared_cache_hides_system_libraries()
    {
        var result = await new MacModuleInspector(Commands(RawFixture("lsof-p")), new Privileges(true), Options())
            .ReadAsync(501, nameFilter: null, CancellationToken.None);

        Assert.Equal(["Finder", "dyld"], result.Modules.Select(m => m.Name));
        Assert.Equal(1218528, result.Modules.Single(m => m.Name == "dyld").SizeBytes);
        Assert.Contains(result.Limitations, l => l.Contains("dyld shared cache", StringComparison.Ordinal));

        var filtered = await new MacModuleInspector(Commands(RawFixture("lsof-p")), new Privileges(true), Options())
            .ReadAsync(501, nameFilter: "DYLD", CancellationToken.None);
        Assert.Equal(["dyld"], filtered.Modules.Select(m => m.Name));
    }
}
