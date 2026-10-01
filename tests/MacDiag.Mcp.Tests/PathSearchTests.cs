using System.Collections;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Handles;
using MacDiag.Mcp.Diagnostics.Processes;
using static MacDiag.Mcp.Tests.HandleTests;

namespace MacDiag.Mcp.Tests;

public sealed class PathSearchTests
{
    private static readonly string[] Firmlinks = ["/Applications", "/Library", "/Users", "/Volumes", "/private", "/usr/local"];

    // The whole machine, as a full listing reports it: names are as the kernel spells them.
    private const string FullListing =
        "p10\0cvim\0u501\0\nf3\0ar\0tREG\0n/private/tmp/notes.txt\0\n" +
        "p20\0ctail\0u501\0\nf4\0ar\0tREG\0n/System/Volumes/Data/Users/a/log.txt\0\n" +
        "p30\0ccat\0u501\0\nf5\0ar\0tREG\0n/Users/a/other.txt\0\n" +
        "p40\0cnc\0u501\0\nf6\0au\0tIPv4\0n127.0.0.1:9->127.0.0.1:5\0\n";

    // lsof -f -- /Users/a/log.txt: matched by device and inode, so a hard link under another name comes back too.
    private const string ByIdentity =
        "p20\0ctail\0u501\0\nf4\0ar\0tREG\0n/System/Volumes/Data/Users/a/log.txt\0\n" +
        "p50\0clinker\0u0\0\nf7\0aw\0tREG\0n/Users/a/alias.txt\0\n";

    private static FakeCommands Lsof(string identity = ByIdentity) => new((program, arguments) =>
        program != "lsof" ? new ExternalResult(1, "", "unexpected")
        : arguments.Contains("--") ? FakeCommands.Ok(identity)
        : FakeCommands.Ok(FullListing));

    private static MacHandleInspector Handles(FakeCommands commands, Func<string, bool>? exists = null) =>
        new(commands, new Privileges(true), MacDiagOptions.FromEnvironment(new Hashtable())) { PathExists = exists ?? (_ => true), Firmlinks = Firmlinks };

    [Theory]
    [InlineData("/Users/a/x", new[] { "/Users/a/x", "/System/Volumes/Data/Users/a/x" })]
    [InlineData("/System/Volumes/Data/Users/a/x", new[] { "/System/Volumes/Data/Users/a/x", "/Users/a/x" })]
    [InlineData("/private/tmp/f", new[] { "/private/tmp/f", "/tmp/f", "/System/Volumes/Data/private/tmp/f" })]
    [InlineData("/tmp/f", new[] { "/tmp/f", "/private/tmp/f", "/System/Volumes/Data/private/tmp/f" })]
    [InlineData("/usr/bin/x", new[] { "/usr/bin/x" })]
    [InlineData("/Usersx/y", new[] { "/Usersx/y" })]
    public void Every_spelling_of_a_path_through_the_firmlinks_and_private_links(string path, string[] spellings)
    {
        Assert.Equal(spellings.Order(StringComparer.Ordinal), PathSpellings.Of(path, Firmlinks).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Firmlinks_come_from_the_system_list_when_it_is_there()
    {
        Assert.Equal(["/Applications", "/Users"], PathSpellings.ParseFirmlinks("/Applications\tApplications\n/Users\tUsers\n\n"));
    }

    [Fact]
    public async Task A_fragment_matches_any_spelling_of_each_open_name()
    {
        // /tmp is a link to /private/tmp, so lsof says /private/tmp/notes.txt; the caller wrote /tmp.
        var result = await Handles(Lsof(), exists: _ => false).SearchAsync("/tmp/notes", includeAllObjectTypes: false, CancellationToken.None);

        Assert.Equal([10], result.Entries.Select(e => e.ProcessId));
    }

    [Fact]
    public async Task A_full_path_finds_every_spelling_and_every_other_name_of_the_same_file_once_each()
    {
        // Review Focus: lsof -- <path> alone would miss the Data-volume spelling; the listing alone would miss the hard link.
        var commands = Lsof();

        var result = await Handles(commands).SearchAsync("/Users/a/log.txt", includeAllObjectTypes: false, CancellationToken.None);

        Assert.Equal([50, 20], result.Entries.Select(e => e.ProcessId));
        Assert.Contains(commands.Calls, c => c.Arguments.Contains("-b"));
        Assert.Contains(commands.Calls, c => c.Arguments.SequenceEqual(["-n", "-P", "-w", Mac.Lsof.Fields, "-f", "--", "/Users/a/log.txt"]));
    }

    [Fact]
    public async Task A_directory_finds_what_is_open_beneath_it()
    {
        var result = await Handles(Lsof(identity: "")).SearchAsync("/Users/a", includeAllObjectTypes: false, CancellationToken.None);

        Assert.Equal([30, 20], result.Entries.Select(e => e.ProcessId));
    }

    [Fact]
    public async Task A_path_that_does_not_exist_is_searched_by_name_only()
    {
        var commands = Lsof();

        await Handles(commands, exists: _ => false).SearchAsync("/Users/a/log.txt", false, CancellationToken.None);

        Assert.DoesNotContain(commands.Calls, c => c.Arguments.Contains("--"));
    }

    [Fact]
    public async Task Sockets_are_searched_only_when_asked()
    {
        var files = await Handles(Lsof()).SearchAsync("127.0.0.1:9", includeAllObjectTypes: false, CancellationToken.None);
        var all = await Handles(Lsof()).SearchAsync("127.0.0.1:9", includeAllObjectTypes: true, CancellationToken.None);

        Assert.Empty(files.Entries);
        Assert.Equal([40], all.Entries.Select(e => e.ProcessId));
    }

    private sealed class Table(params ProcessRecord[] processes) : IProcessTable
    {
        public Task<ProcessTable> ReadAsync(CancellationToken cancellationToken) => Task.FromResult(new ProcessTable(processes, []));
    }

    private static ProcessRecord Process(int pid, string? executable) =>
        new(pid, 1, "p", "S", null, "", 0, 0, executable, null);

    private static MacLockInspector Locks(string lsof, bool elevated = true, IProcessTable? table = null, Func<string, bool>? exists = null) =>
        new(new FakeCommands((_, _) => FakeCommands.Ok(lsof)), table ?? new Table(), new Privileges(elevated), MacDiagOptions.FromEnvironment(new Hashtable()))
        {
            PathExists = exists ?? (_ => true),
            Firmlinks = Firmlinks,
        };

    [Fact]
    public async Task Each_holder_says_how_it_holds_the_path_and_only_its_own_executable_counts_as_executing()
    {
        var lsof =
            "p60\0capp\0u501\0\nftxt\0a \0tREG\0n/Users/a/lib.dylib\0\n" +
            "p61\0clib\0u501\0\nftxt\0a \0tREG\0n/Users/a/lib.dylib\0\n" +
            "p62\0cshell\0u501\0\nfcwd\0a \0tDIR\0n/Users/a/lib.dylib\0\n" +
            "p63\0cw\0u501\0\nf9\0aw\0tREG\0n/Users/a/lib.dylib\0\n";

        var result = await Locks(lsof, table: new Table(Process(60, "/System/Volumes/Data/Users/a/lib.dylib"), Process(61, "/usr/bin/other")))
            .QueryAsync("/Users/a/lib.dylib", CancellationToken.None);

        Assert.Equal(
            [(60, LockHolderKind.Executing), (61, LockHolderKind.Mapped), (62, LockHolderKind.WorkingDirectory), (63, LockHolderKind.Open)],
            result.Holders.Select(h => (h.ProcessId, h.Kind)));
        Assert.Equal("write", result.Holders.Single(h => h.ProcessId == 63).Access);
    }

    [Fact]
    public async Task Every_answer_says_lock_state_is_not_visible_and_is_exhaustive_only_as_root()
    {
        var root = await Locks("", elevated: true).QueryAsync("/Users/a/x", CancellationToken.None);
        var user = await Locks("", elevated: false).QueryAsync("/Users/a/x", CancellationToken.None);

        Assert.Contains(root.Limitations, l => l.Contains("does not report lock state", StringComparison.Ordinal));
        Assert.True(root.Exhaustive);
        Assert.False(user.Exhaustive);
    }

    [Fact]
    public async Task A_mount_point_is_asked_about_as_that_directory_alone()
    {
        // lsof -f -- / means the root directory itself, not every open file on the volume.
        var commands = new FakeCommands((_, _) => FakeCommands.Ok(""));
        var inspector = new MacLockInspector(commands, new Table(), new Privileges(true), MacDiagOptions.FromEnvironment(new Hashtable()))
        {
            PathExists = _ => true,
            Firmlinks = Firmlinks,
        };

        await inspector.QueryAsync("/", CancellationToken.None);

        Assert.Equal(["-n", "-P", "-w", Mac.Lsof.Fields, "-f", "--", "/"], commands.Calls.Single().Arguments);
    }

    [Fact]
    public async Task A_path_that_does_not_exist_runs_nothing_and_says_so()
    {
        var commands = new FakeCommands((_, _) => FakeCommands.Ok(""));
        var inspector = new MacLockInspector(commands, new Table(), new Privileges(true), MacDiagOptions.FromEnvironment(new Hashtable()))
        {
            PathExists = _ => false,
            Firmlinks = Firmlinks,
        };

        var result = await inspector.QueryAsync("/Users/a/nope", CancellationToken.None);

        Assert.False(result.PathExists);
        Assert.Empty(commands.Calls);
    }
}
