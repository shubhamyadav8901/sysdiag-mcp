using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Tests;

public sealed class StatLinesTests
{
    /// <summary>One line of <see cref="StatLines.Format"/>, as BSD stat would print it.</summary>
    internal static string Line(string path, int uid, int gid, string mode, string type, string flags = "-", long size = 0, long modified = 1727762400) =>
        $"{uid}\t{gid}\t{mode}\t{flags}\t{size}\t{modified}\t{type}\t{path}";

    /// <summary>A stat that answers for the paths it knows, prints nothing for the rest, and fails like BSD stat does.</summary>
    internal static ExternalResult Answer(IReadOnlyDictionary<string, string> lines, IReadOnlyList<string> arguments, IReadOnlySet<string>? denied = null)
    {
        var paths = arguments.SkipWhile(a => a != "--").Skip(1).ToList();
        var known = paths.Where(lines.ContainsKey).Select(p => lines[p]).ToList();
        var missing = paths.Where(p => !lines.ContainsKey(p))
            .Select(p => denied?.Contains(p) == true ? $"stat: {p}: stat: Permission denied" : $"stat: {p}: stat: No such file or directory")
            .ToList();
        return new ExternalResult(missing.Count == 0 ? 0 : 1, string.Join('\n', known) + "\n", string.Join('\n', missing));
    }

    [Fact]
    public async Task A_long_list_of_paths_is_statted_in_batches_so_no_argument_list_outgrows_the_system_limit()
    {
        var paths = Enumerable.Range(0, 600).Select(i => $"/p/{i}").ToList();
        var lines = paths.ToDictionary(p => p, p => Line(p, 0, 0, "0644", "Regular File"));
        var commands = new FakeCommands((_, args) => Answer(lines, args));

        var stats = await StatLines.StatAsync(commands, paths, TimeSpan.FromSeconds(5), CancellationToken.None);

        Assert.Equal(600, stats.Count);
        Assert.Equal(3, commands.Calls.Count);
        Assert.All(commands.Calls, c => Assert.True(c.Arguments.Count <= StatLines.Batch + 3, c.Arguments.Count.ToString(System.Globalization.CultureInfo.InvariantCulture)));
    }

    [Fact]
    public async Task A_path_privacy_protection_refuses_counts_as_out_of_sight_too()
    {
        // A root daemon without Full Disk Access is refused by TCC with EPERM, not EACCES.
        var commands = new FakeCommands((_, _) => new ExternalResult(1, "\n", "stat: /Users/a/Library/Mail: stat: Operation not permitted\n"));

        var outcome = await StatLines.StatOutcomeAsync(commands, ["/Users/a/Library/Mail"], TimeSpan.FromSeconds(5), CancellationToken.None);

        Assert.Equal(["/Users/a/Library/Mail"], outcome.Denied);
    }

    [Fact]
    public async Task A_path_stat_may_not_look_at_is_told_apart_from_one_that_does_not_exist()
    {
        var lines = new Dictionary<string, string> { ["/a"] = Line("/a", 0, 0, "0644", "Regular File") };
        var commands = new FakeCommands((_, args) => Answer(lines, args, new HashSet<string> { "/Users/bob/x: odd" }));

        var outcome = await StatLines.StatOutcomeAsync(commands, ["/a", "/gone", "/Users/bob/x: odd"], TimeSpan.FromSeconds(5), CancellationToken.None);

        Assert.Equal(["/a"], outcome.Lines.Keys);
        Assert.Equal(["/Users/bob/x: odd"], outcome.Denied);
    }

    [Fact]
    public void A_stat_line_gives_owner_group_mode_flags_size_time_kind_and_a_name_with_spaces()
    {
        var line = StatLines.Parse(Line("/Users/a/My Folder/x y", 501, 20, "0644", "Regular File", "uchg,hidden", 42, 1727762401)).Single();

        Assert.Equal("/Users/a/My Folder/x y", line.Path);
        Assert.Equal((501, 20, 0b110_100_100), (line.Uid, line.Gid, line.Mode));
        Assert.Equal(["uchg", "hidden"], line.Flags);
        Assert.Equal((42L, 1727762401L, StatKind.File), (line.Size, line.ModifiedEpoch, line.Kind));
    }

    [Theory]
    [InlineData("Directory", StatKind.Directory)]
    [InlineData("Regular File", StatKind.File)]
    [InlineData("Symbolic Link", StatKind.Link)]
    [InlineData("Socket", StatKind.Socket)]
    [InlineData("Fifo File", StatKind.Fifo)]
    [InlineData("Character Device", StatKind.CharacterDevice)]
    [InlineData("Block Device", StatKind.BlockDevice)]
    [InlineData("Whiteout", StatKind.Other)]
    public void Every_kind_stat_names_is_told_apart(string type, StatKind kind)
    {
        Assert.Equal(kind, StatLines.Parse(Line("/p", 0, 0, "0644", type)).Single().Kind);
    }

    [Theory]
    [InlineData("/usr/local/bin/../bin/./tool", "/usr/local/bin/tool")]
    [InlineData("//a///b/", "/a/b")]
    [InlineData("/..", "/")]
    [InlineData("relative/x", null)]
    [InlineData("C:\\Windows", null)]
    public void A_mac_path_is_normalised_lexically_the_same_on_every_os(string path, string? expected)
    {
        Assert.Equal(expected, MacDiag.Mcp.Mac.MacPaths.Lexical(path));
    }

    [Fact]
    public void No_flags_is_an_empty_list_and_a_malformed_line_is_skipped()
    {
        var lines = StatLines.Parse(Line("/p", 0, 0, "0644", "Regular File") + "\nnot a stat line\n");

        Assert.Empty(Assert.Single(lines).Flags);
    }

    [Fact]
    public void The_arguments_put_every_path_after_the_end_of_options()
    {
        Assert.Equal(["-f", StatLines.Format, "--", "-rf", "/x"], StatLines.Arguments(["-rf", "/x"]));
        Assert.Contains('\t', StatLines.Format);
    }

    [Theory]
    [InlineData("/a/b\nc", true)]
    [InlineData("/a/b\tc", true)]
    [InlineData("/a/\u001bb", true)]
    [InlineData("/a/b c", false)]
    [InlineData("/a/ü", false)]
    public void A_name_with_a_control_character_is_recognised(string path, bool expected)
    {
        Assert.Equal(expected, StatLines.HasControlCharacter(path));
    }

    [Theory]
    [InlineData(0, 0, "0755", false)]
    [InlineData(501, 20, "0755", true)]     // owned by someone else
    [InlineData(0, 0, "0757", true)]        // anyone can write
    [InlineData(0, 20, "0775", true)]       // staff can write
    [InlineData(0, 80, "0775", false)]      // admin can write: admins can become root anyway
    [InlineData(0, 0, "0775", false)]       // wheel can write
    public void Writable_by_others_means_another_owner_or_a_write_bit_for_an_untrusted_group_or_everyone(int uid, int gid, string mode, bool expected)
    {
        var line = StatLines.Parse(Line("/p", uid, gid, mode, "Directory")).Single();

        Assert.Equal(expected, StatLines.WritableByOthers(line, new HashSet<int> { 0 }));
    }

    [Fact]
    public void A_links_own_mode_means_nothing()
    {
        var line = StatLines.Parse(Line("/p", 0, 20, "0777", "Symbolic Link")).Single();

        Assert.False(StatLines.WritableByOthers(line, new HashSet<int> { 0 }));
    }

    [Fact]
    public async Task StatAsync_keys_lines_by_path_skips_names_with_control_characters_and_reads_through_a_partial_failure()
    {
        var lines = new Dictionary<string, string> { ["/a"] = Line("/a", 0, 0, "0644", "Regular File") };
        var commands = new FakeCommands((_, args) => Answer(lines, args));

        var stats = await StatLines.StatAsync(commands, ["/a", "/missing", "/bad\nname"], TimeSpan.FromSeconds(5), CancellationToken.None);

        Assert.Equal(["/a"], stats.Keys);
        Assert.DoesNotContain(commands.Calls.Single().Arguments, a => a.Contains('\n', StringComparison.Ordinal));
    }

    [Fact]
    public async Task StatAsync_runs_nothing_when_there_is_nothing_to_stat()
    {
        var commands = new FakeCommands((_, _) => throw new InvalidOperationException("stat ran"));

        Assert.Empty(await StatLines.StatAsync(commands, [], TimeSpan.FromSeconds(5), CancellationToken.None));
    }
}
