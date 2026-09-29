using System.Security.Cryptography;
using Diag.Mcp.Server.Files;
using Microsoft.Extensions.Logging.Abstractions;

namespace Diag.Mcp.Server.Tests;

/// <summary>
/// The scope boundary is the security-critical part: a write lands freely only inside a windiag-owned
/// directory, and anywhere else needs the arbitrary-write grant.
/// </summary>
public sealed class FileReceiverTests : IDisposable
{
    private readonly string _artifactDir;
    private readonly string _outsideDir;

    public FileReceiverTests()
    {
        _artifactDir = Path.Combine(Path.GetTempPath(), $"windiag-artifacts-{Guid.NewGuid():N}");
        _outsideDir = Path.Combine(Path.GetTempPath(), $"windiag-outside-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_artifactDir);
        Directory.CreateDirectory(_outsideDir);
    }

    public void Dispose()
    {
        foreach (var dir in new[] { _artifactDir, _outsideDir })
        {
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }

    private FileReceiver Receiver(bool allowArbitrary = false) =>
        new(new FileTransferOptions(_artifactDir, allowArbitrary, false,
                "WINDIAG_ALLOW_ARBITRARY_WRITE=1", "WINDIAG_ALLOW_ARBITRARY_READ=1"),
            NullLogger<FileReceiver>.Instance);

    private static byte[] Bytes(string s) => System.Text.Encoding.UTF8.GetBytes(s);

    private static string Sha(byte[] b) => Convert.ToHexString(SHA256.HashData(b));

    [UnixFact]
    public void A_link_inside_an_owned_directory_does_not_widen_write_scope()
    {
        // The owned directory is judged by where a path really lands. A link planted inside it that
        // points elsewhere must not turn "confined to my directories" into "anywhere the link goes".
        Directory.CreateSymbolicLink(Path.Combine(_artifactDir, "escape"), _outsideDir);

        var ex = Assert.Throws<FileTransferException>(() => Receiver().Receive(
            new FileWriteRequest(Path.Combine(_artifactDir, "escape", "planted.bin"), [1]), CancellationToken.None));

        Assert.Contains("arbitrary write", ex.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(_outsideDir, "planted.bin")));
    }

    [WindowsFact]
    public void A_junction_inside_an_owned_directory_does_not_widen_write_scope()
    {
        // The Windows form of the same escape. A junction needs no privilege to create, unlike a symlink.
        var junction = Path.Combine(_artifactDir, "escape");
        using (var mklink = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                   "cmd.exe", $"/c mklink /J \"{junction}\" \"{_outsideDir}\"") { CreateNoWindow = true, UseShellExecute = false })!)
        {
            mklink.WaitForExit();
            Assert.Equal(0, mklink.ExitCode);
        }

        try
        {
            var ex = Assert.Throws<FileTransferException>(() => Receiver().Receive(
                new FileWriteRequest(Path.Combine(junction, "planted.bin"), [1]), CancellationToken.None));

            Assert.Contains("arbitrary write", ex.Message, StringComparison.Ordinal);
            Assert.False(File.Exists(Path.Combine(_outsideDir, "planted.bin")));
        }
        finally
        {
            // Removed by itself, non-recursively: a recursive delete of the folder holding a junction is
            // refused with access denied, which would fail the test on cleanup rather than on its claim.
            Directory.Delete(junction);
        }
    }

    [Fact]
    public void Writes_freely_into_the_artifact_directory_with_no_flag()
    {
        var target = Path.Combine(_artifactDir, "staged.bin");
        var content = Bytes("hello windiag");

        var result = Receiver().Receive(new FileWriteRequest(target, content), CancellationToken.None);

        Assert.Equal(WriteScope.WinDiag, result.Scope);
        Assert.True(File.Exists(target));
        Assert.Equal(content, File.ReadAllBytes(target));
        Assert.Equal(Sha(content), result.Sha256);
    }

    [Fact]
    public void Creates_missing_subdirectories_under_an_owned_directory()
    {
        // Staging often targets a nested path that does not exist yet.
        var target = Path.Combine(_artifactDir, "nested", "deep", "staged.bin");

        var result = Receiver().Receive(new FileWriteRequest(target, Bytes("x")), CancellationToken.None);

        Assert.True(File.Exists(target));
        Assert.Equal(WriteScope.WinDiag, result.Scope);
    }

    [Fact]
    public void Refuses_a_write_outside_owned_directories_without_the_grant()
    {
        var target = Path.Combine(_outsideDir, "evil.dll");

        var ex = Assert.Throws<FileTransferException>(
            () => Receiver(allowArbitrary: false).Receive(new FileWriteRequest(target, Bytes("x")), CancellationToken.None));

        Assert.Contains("WINDIAG_ALLOW_ARBITRARY_WRITE", ex.Message);
        Assert.False(File.Exists(target), "the file must not have been written when the write was refused");
    }

    [Fact]
    public void Allows_a_write_anywhere_with_the_grant()
    {
        var target = Path.Combine(_outsideDir, "planted.txt");

        var result = Receiver(allowArbitrary: true).Receive(
            new FileWriteRequest(target, Bytes("anywhere")), CancellationToken.None);

        Assert.Equal(WriteScope.Arbitrary, result.Scope);
        Assert.True(File.Exists(target));
    }

    [Fact]
    public void Judges_a_dotdot_escape_by_where_it_actually_lands()
    {
        // The classic scope bypass: a path spelled to look like it is under the artifact dir but which
        // climbs out. GetFullPath resolves it, so it is judged as the outside path it really is and
        // refused without the grant.
        var escape = Path.Combine(_artifactDir, "..", Path.GetFileName(_outsideDir), "escaped.txt");

        var ex = Assert.Throws<FileTransferException>(
            () => Receiver(allowArbitrary: false).Receive(new FileWriteRequest(escape, Bytes("x")), CancellationToken.None));

        Assert.Contains("outside the directories", ex.Message);
    }

    [Fact]
    public void Does_not_treat_a_sibling_with_a_shared_prefix_as_inside()
    {
        // C:\...\windiag-artifacts-XXXX-extra must not count as being under the artifact dir just
        // because the name starts the same way. This is why the check appends a separator.
        var sibling = _artifactDir + "-extra";
        Directory.CreateDirectory(sibling);
        try
        {
            var target = Path.Combine(sibling, "f.bin");

            Assert.Throws<FileTransferException>(
                () => Receiver(allowArbitrary: false).Receive(new FileWriteRequest(target, Bytes("x")), CancellationToken.None));
        }
        finally
        {
            Directory.Delete(sibling, recursive: true);
        }
    }

    [Fact]
    public void Verifies_the_hash_and_rolls_back_on_mismatch()
    {
        var target = Path.Combine(_artifactDir, "checked.bin");

        var ex = Assert.Throws<FileTransferException>(() => Receiver().Receive(
            new FileWriteRequest(target, Bytes("real content"), ExpectedSha256: Sha(Bytes("different"))),
            CancellationToken.None));

        Assert.Contains("has been deleted", ex.Message);
        Assert.False(File.Exists(target), "a file that failed verification must not be left behind");
    }

    [Fact]
    public void Accepts_a_matching_hash()
    {
        var target = Path.Combine(_artifactDir, "verified.bin");
        var content = Bytes("exact");

        var result = Receiver().Receive(
            new FileWriteRequest(target, content, ExpectedSha256: Sha(content)), CancellationToken.None);

        Assert.Equal(Sha(content), result.Sha256);
        Assert.True(File.Exists(target));
    }

    [Fact]
    public void Refuses_to_overwrite_when_told_not_to()
    {
        var target = Path.Combine(_artifactDir, "existing.bin");
        File.WriteAllBytes(target, Bytes("original"));

        var ex = Assert.Throws<FileTransferException>(() => Receiver().Receive(
            new FileWriteRequest(target, Bytes("replacement"), Overwrite: false), CancellationToken.None));

        Assert.Contains("already exists", ex.Message);
        Assert.Equal("original", File.ReadAllText(target));
    }

    [Fact]
    public void Reports_that_it_replaced_an_existing_file()
    {
        var target = Path.Combine(_artifactDir, "replaced.bin");
        File.WriteAllBytes(target, Bytes("old"));

        var result = Receiver().Receive(new FileWriteRequest(target, Bytes("new")), CancellationToken.None);

        Assert.True(result.Overwrote);
        Assert.Equal("new", File.ReadAllText(target));
    }

    [Fact]
    public void Assembles_a_file_from_chunks_and_verifies_the_whole_at_the_end()
    {
        // The path a large binary takes on a 32-bit server, where one big base64 argument OOMs: first
        // chunk fresh, the rest appended, the hash of the whole assembled file checked only on the last.
        var target = Path.Combine(_artifactDir, "chunked.bin");
        var whole = System.Text.Encoding.UTF8.GetBytes(new string('A', 1000) + new string('B', 1000) + "tail");
        var wholeSha = Sha(whole);
        var recv = Receiver();

        recv.Receive(new FileWriteRequest(target, whole[..1000], Append: false), CancellationToken.None);
        recv.Receive(new FileWriteRequest(target, whole[1000..2000], Append: true), CancellationToken.None);
        var final = recv.Receive(
            new FileWriteRequest(target, whole[2000..], ExpectedSha256: wholeSha, Append: true),
            CancellationToken.None);

        Assert.Equal(whole, File.ReadAllBytes(target));
        Assert.Equal(wholeSha, final.Sha256);
    }

    [Fact]
    public void Rolls_back_the_whole_file_when_an_assembled_chunk_sequence_fails_verification()
    {
        // A corrupt chunk anywhere shows up as a whole-file hash mismatch on the last call, and the
        // assembled file is deleted -- so a bad transfer never survives to be swapped in by update_self.
        var target = Path.Combine(_artifactDir, "chunked-bad.bin");
        var recv = Receiver();

        recv.Receive(new FileWriteRequest(target, Bytes("first"), Append: false), CancellationToken.None);

        Assert.Throws<FileTransferException>(() => recv.Receive(
            new FileWriteRequest(target, Bytes("second"), ExpectedSha256: Sha(Bytes("not the whole thing")), Append: true),
            CancellationToken.None));

        Assert.False(File.Exists(target));
    }

    [Fact]
    public void Rejects_a_chunk_that_fails_its_own_hash_before_touching_disk()
    {
        // The per-chunk check: a chunk corrupted in transit is caught in memory, and because nothing is
        // written the file is left exactly as it was -- so the caller can re-send that chunk. Here the
        // first chunk lands, then a second chunk arrives with a hash that does not match its bytes.
        var target = Path.Combine(_artifactDir, "chunk-guard.bin");
        var recv = Receiver();
        recv.Receive(new FileWriteRequest(target, Bytes("good first chunk"), Append: false), CancellationToken.None);
        var before = File.ReadAllBytes(target);

        var ex = Assert.Throws<FileTransferException>(() => recv.Receive(
            new FileWriteRequest(target, Bytes("second chunk"), Append: true, ChunkSha256: Sha(Bytes("wrong"))),
            CancellationToken.None));

        Assert.Contains("arrived corrupted", ex.Message);
        Assert.Equal(before, File.ReadAllBytes(target));   // the rejected chunk changed nothing
    }

    [Fact]
    public void Accepts_a_chunk_whose_hash_matches_its_bytes()
    {
        var target = Path.Combine(_artifactDir, "chunk-ok.bin");
        var content = Bytes("verified chunk");

        Receiver().Receive(
            new FileWriteRequest(target, content, Append: false, ChunkSha256: Sha(content)), CancellationToken.None);

        Assert.Equal(content, File.ReadAllBytes(target));
    }

    [Fact]
    public void An_append_chunk_is_still_bound_by_scope()
    {
        // Chunking must not become a scope bypass: an append outside the owned dirs is refused just like
        // a fresh write would be.
        var target = Path.Combine(_outsideDir, "chunked-escape.bin");

        Assert.Throws<FileTransferException>(() => Receiver(allowArbitrary: false).Receive(
            new FileWriteRequest(target, Bytes("x"), Append: true), CancellationToken.None));
    }
}

public sealed class PutFileToolTests
{
    private sealed class StubReceiver : IFileReceiver
    {
        public FileWriteRequest? Last { get; private set; }

        public FileWriteResult Receive(FileWriteRequest request, CancellationToken cancellationToken)
        {
            Last = request;
            return new FileWriteResult(request.Path, request.Content.LongLength, "ABC", WriteScope.WinDiag, false);
        }
    }

    [Fact]
    public void Decodes_base64_into_the_bytes_the_receiver_writes()
    {
        var stub = new StubReceiver();
        var tool = new FileTools(stub);
        var payload = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("windiag"));

        tool.PutFile(@"C:\WinDiag\x.bin", payload);

        Assert.Equal("windiag", System.Text.Encoding.UTF8.GetString(stub.Last!.Content));
    }

    [Fact]
    public void Rejects_malformed_base64_with_an_actionable_message()
    {
        var tool = new FileTools(new StubReceiver());

        var ex = Assert.Throws<FileTransferException>(
            () => tool.PutFile(@"C:\WinDiag\x.bin", "not base64!!!"));

        Assert.Contains("base64", ex.Message);
    }

    [Fact]
    public void Empty_content_writes_an_empty_file_rather_than_being_refused()
    {
        // The relay sends a zero-byte file as one call with contentBase64 = "", so refusing empty
        // content made pushing an empty file impossible. An empty payload is a valid file.
        var stub = new StubReceiver();
        var tool = new FileTools(stub);

        tool.PutFile(Path.Combine(Path.GetTempPath(), "empty.bin"), "");

        Assert.NotNull(stub.Last);
        Assert.Empty(stub.Last!.Content);
    }

    [Fact]
    public void Missing_content_is_refused_so_a_malformed_call_cannot_empty_a_file()
    {
        // Only "" means an empty file. A null is a call that forgot the content, and with overwrite on by
        // default, accepting it would truncate whatever is at the path to zero bytes.
        var stub = new StubReceiver();
        var tool = new FileTools(stub);

        var ex = Assert.Throws<FileTransferException>(
            () => tool.PutFile(Path.Combine(Path.GetTempPath(), "kept.bin"), null!));

        Assert.Contains("contentBase64", ex.Message, StringComparison.Ordinal);
        Assert.Null(stub.Last);
    }

    [Fact]
    public void Render_states_the_hash_and_flags_an_arbitrary_write()
    {
        var scoped = FileTools.Render(new FileWriteResult(@"C:\WinDiag\a", 10, "HASH", WriteScope.WinDiag, false));
        Assert.Contains("Wrote", scoped);
        Assert.Contains("HASH", scoped);
        Assert.DoesNotContain("arbitrary-write grant", scoped);

        var arbitrary = FileTools.Render(new FileWriteResult(@"C:\Windows\b", 10, "HASH", WriteScope.Arbitrary, true));
        Assert.Contains("Replaced", arbitrary);
        Assert.Contains("arbitrary-write grant", arbitrary);
    }
}
