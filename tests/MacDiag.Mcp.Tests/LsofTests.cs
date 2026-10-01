using MacDiag.Mcp.Mac;
using MacDiag.Mcp.Mac.Parsers;
using static MacDiag.Mcp.Tests.SystemOverviewTests;

namespace MacDiag.Mcp.Tests;

public sealed class LsofTests
{
    /// <summary>The readable fixture form as lsof -F0 writes it: each field NUL-terminated, each set ending in a newline.</summary>
    internal static string Raw(string readable) =>
        string.Concat(readable.Split("\n--", StringSplitOptions.RemoveEmptyEntries)
            .Select(set => set.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            .Where(fields => fields.Length > 0)
            .Select(fields => string.Concat(fields.Select(f => f + "\0")) + "\n"));

    internal static string RawFixture(string name) => Raw(Fixture(Unverified, name));

    [Fact]
    public void Fields_group_into_processes_and_their_files_with_access_type_and_name()
    {
        var process = Assert.Single(LsofFields.Parse(RawFixture("lsof-p")));

        Assert.Equal((501, (int?)1, "Finder", (long?)501), (process.ProcessId, process.ParentProcessId, process.Command, process.UserId));
        Assert.Equal(7, process.Files.Count);
        Assert.Contains(process.Files, f => f.Descriptor == "txt" && f.Name == "/usr/lib/dyld" && f.Access is null);
        Assert.Contains(process.Files, f => f.Descriptor == "3" && f.Access == "r" && f.Type == "REG" && f.Inode == 345678);
        Assert.Equal("0x1234abcd", process.Files.Single(f => f.Descriptor == "4").KernelAddress);
    }

    [Fact]
    public void An_escaped_name_is_decoded_back_to_its_characters()
    {
        // In the C locale lsof writes each non-ASCII byte as \xNN and a tab as \t.
        var file = LsofFields.Parse(RawFixture("lsof-p"))[0].Files.Single(f => f.Descriptor == "3");

        Assert.Equal("/Users/a/café\tnotes.txt", file.Name);
    }

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("caf\\xc3\\xa9", "café")]
    [InlineData("a\\nb\\rc\\bd\\fe", "a\nb\rc\bd\fe")]
    [InlineData("half\\xc3", "half\\xc3")]   // not valid UTF-8: kept as lsof printed it
    [InlineData("back\\slash", "back\\slash")]
    public void Lsof_escapes_decode_and_anything_unrecognised_is_left_alone(string printed, string decoded)
    {
        Assert.Equal(decoded, LsofEscapes.Decode(printed));
    }

    [Fact]
    public void A_raw_newline_inside_a_field_stays_one_file_and_cannot_start_a_record()
    {
        // Review Focus 1: NUL termination is why -F0; a newline inside a value is data, not a record break.
        var files = LsofFields.Parse("p7\0cx\0\nf3\0tREG\0n/tmp/a\nfake\0\nf4\0tREG\0n/tmp/b\0\n")[0].Files;

        Assert.Equal(["/tmp/a\nfake", "/tmp/b"], files.Select(f => f.Name));
    }

    [Fact]
    public void Tcp_state_and_protocol_come_from_their_own_fields()
    {
        var sshd = LsofFields.Parse(RawFixture("lsof-i")).Single(p => p.Command == "sshd");

        Assert.Equal(("TCP", "LISTEN", "*:22"), (sshd.Files[0].Protocol, sshd.Files[0].TcpState, sshd.Files[0].Name));
    }

    [Fact]
    public void A_truncated_stream_keeps_what_was_complete_and_drops_the_partial_field()
    {
        var raw = RawFixture("lsof-p");

        var files = Assert.Single(LsofFields.Parse(raw[..^5])).Files;

        Assert.Null(files.Single(f => f.Descriptor == "6").Name);
        Assert.DoesNotContain(files, f => f.Name?.Contains("myf", StringComparison.Ordinal) == true);
    }

    [Theory]
    [InlineData(1, "", false)]
    [InlineData(1, "lsof: status error on /nope: No such file or directory", true)]
    [InlineData(0, "lsof: WARNING: can't stat() smbfs file system /Volumes/share", false)]
    [InlineData(2, "", true)]
    public void Exit_one_with_no_message_means_none_and_with_a_message_is_an_error(int exit, string stderr, bool error)
    {
        // Review Focus 3.
        Assert.Equal(error, Lsof.IsError(exit, stderr));
    }

    [Fact]
    public async Task The_call_always_asks_for_numeric_nul_terminated_fields_and_a_full_listing_does_not_block()
    {
        var commands = new FakeCommands((_, _) => FakeCommands.Ok(RawFixture("lsof-p")));

        await Lsof.RunAsync(commands, ["--", "/tmp/x"], fullListing: true, TimeSpan.FromSeconds(5), CancellationToken.None);
        await Lsof.RunAsync(commands, ["-p", "501"], fullListing: false, TimeSpan.FromSeconds(5), CancellationToken.None);

        Assert.Equal(["-n", "-P", "-w", "-F0pcuRfatdDsinPT", "-b", "--", "/tmp/x"], commands.Calls[0].Arguments);
        Assert.Equal(["-n", "-P", "-w", "-F0pcuRfatdDsinPT", "-p", "501"], commands.Calls[1].Arguments);
    }

    [Fact]
    public async Task An_lsof_error_reaches_the_caller_with_its_message()
    {
        var commands = new FakeCommands((_, _) => new ExternalResult(1, "", "lsof: status error on /nope"));

        var ex = await Assert.ThrowsAsync<LsofException>(() =>
            Lsof.RunAsync(commands, ["--", "/nope"], fullListing: false, TimeSpan.FromSeconds(5), CancellationToken.None));

        Assert.Contains("status error", ex.Message, StringComparison.Ordinal);
    }
}
