using System.Security.Cryptography;
using Diag.Mcp.Server.Files;
using Microsoft.Extensions.Logging.Abstractions;

namespace Diag.Mcp.Server.Tests;

/// <summary>
/// Reading a file back off the host. The scope boundary is the security-critical part and is the same
/// one the write side is held to: a read lands freely only inside a windiag-owned directory, and
/// anywhere else needs the arbitrary-read grant.
/// </summary>
public sealed class FileSenderTests : IDisposable
{
    private readonly string _artifactDir;
    private readonly string _outsideDir;

    public FileSenderTests()
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

    private FileSender Sender(bool allowArbitrary = false) =>
        new(new FileTransferOptions(_artifactDir, false, allowArbitrary,
                "WINDIAG_ALLOW_ARBITRARY_WRITE=1", "WINDIAG_ALLOW_ARBITRARY_READ=1"),
            NullLogger<FileSender>.Instance);

    /// <summary>Writes a file of <paramref name="size"/> bytes with a recognisable, position-dependent pattern.</summary>
    private string Fixture(string name, int size, string? directory = null)
    {
        var path = Path.Combine(directory ?? _artifactDir, name);
        var bytes = new byte[size];
        for (var i = 0; i < size; i++)
        {
            bytes[i] = (byte)(i % 251);   // prime, so a wrong offset does not accidentally line up
        }

        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static string Sha(byte[] b) => Convert.ToHexString(SHA256.HashData(b));

    [UnixFact]
    public void A_link_inside_an_owned_directory_does_not_widen_read_scope()
    {
        File.WriteAllText(Path.Combine(_outsideDir, "secret.txt"), "not for you");
        File.CreateSymbolicLink(Path.Combine(_artifactDir, "looks-owned.txt"), Path.Combine(_outsideDir, "secret.txt"));

        var ex = Assert.Throws<FileTransferException>(() => Sender().Read(
            new FileReadRequest(Path.Combine(_artifactDir, "looks-owned.txt")), CancellationToken.None));

        Assert.Contains("arbitrary read", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Reads_freely_from_the_artifact_directory_with_no_flag()
    {
        // The whole point: capture_dump and capture_activity write here, so retrieving what the server
        // produced must not need a grant.
        var path = Fixture("capture.dmp", 1024);

        var result = Sender().Read(new FileReadRequest(path), CancellationToken.None);

        Assert.Equal(WriteScope.Owned, result.Scope);
        Assert.Equal(1024, result.TotalBytes);
        Assert.Equal(1024, result.Length);
        Assert.True(result.EndOfFile);
    }

    [Fact]
    public void Refuses_a_path_outside_the_owned_directories_unless_arbitrary_read_is_on()
    {
        var path = Fixture("secrets.txt", 32, _outsideDir);

        var ex = Assert.Throws<FileTransferException>(
            () => Sender().Read(new FileReadRequest(path), CancellationToken.None));

        Assert.Contains("WINDIAG_ALLOW_ARBITRARY_READ", ex.Message);
    }

    [Fact]
    public void Reads_outside_when_arbitrary_read_is_enabled()
    {
        var path = Fixture("secrets.txt", 32, _outsideDir);

        var result = Sender(allowArbitrary: true).Read(new FileReadRequest(path), CancellationToken.None);

        Assert.Equal(WriteScope.Arbitrary, result.Scope);
        Assert.Equal(32, result.Length);
    }

    [Fact]
    public void A_path_that_climbs_out_of_an_owned_directory_is_judged_by_where_it_lands()
    {
        // The classic scope escape: spelled as if it were inside, actually outside.
        Fixture("secrets.txt", 16, _outsideDir);
        var climbing = Path.Combine(_artifactDir, "..", Path.GetFileName(_outsideDir), "secrets.txt");

        Assert.Throws<FileTransferException>(
            () => Sender().Read(new FileReadRequest(climbing), CancellationToken.None));
    }

    [Fact]
    public void Slices_walk_the_file_and_reassemble_to_the_original()
    {
        const int size = 5000;
        var path = Fixture("trace.csv", size);
        var original = File.ReadAllBytes(path);
        var sender = Sender();

        var assembled = new List<byte>(size);
        long offset = 0;
        var slices = 0;

        while (true)
        {
            var slice = sender.Read(new FileReadRequest(path, offset, 1024), CancellationToken.None);
            slices++;

            // Every slice is self-verifying, which is what lets a caller re-request just that offset.
            Assert.Equal(Sha(slice.Content), slice.ChunkSha256);

            assembled.AddRange(slice.Content);
            offset += slice.Length;

            if (slice.EndOfFile)
            {
                break;
            }
        }

        Assert.Equal(5, slices);                       // 4 full slices plus a 904-byte remainder
        Assert.Equal(original, assembled.ToArray());
    }

    [Fact]
    public void The_whole_file_hash_is_returned_only_when_it_is_asked_for()
    {
        // It rereads the entire file, so a chunked fetch that asked every time would be quadratic.
        var path = Fixture("dump.dmp", 2048);
        var expected = Sha(File.ReadAllBytes(path));

        Assert.Null(Sender().Read(new FileReadRequest(path, 0, 512), CancellationToken.None).Sha256);

        var withHash = Sender().Read(
            new FileReadRequest(path, 0, 512, IncludeWholeFileHash: true), CancellationToken.None);

        Assert.Equal(expected, withHash.Sha256);
        Assert.NotEqual(withHash.ChunkSha256, withHash.Sha256);   // the slice is not the whole file
    }

    [Fact]
    public void A_length_over_the_cap_is_clamped_rather_than_refused()
    {
        var path = Fixture("big.bin", FileSender.MaxLength + 5000);

        var result = Sender().Read(
            new FileReadRequest(path, 0, int.MaxValue), CancellationToken.None);

        Assert.Equal(FileSender.MaxLength, result.Length);
        Assert.False(result.EndOfFile);
    }

    [Fact]
    public void A_length_of_zero_takes_the_default()
    {
        var path = Fixture("big.bin", FileSender.DefaultLength * 2);

        var result = Sender().Read(new FileReadRequest(path), CancellationToken.None);

        Assert.Equal(FileSender.DefaultLength, result.Length);
    }

    [Fact]
    public void Explains_a_file_that_does_not_exist()
    {
        var missing = Path.Combine(_artifactDir, "not-here.dmp");

        var ex = Assert.Throws<FileTransferException>(
            () => Sender().Read(new FileReadRequest(missing), CancellationToken.None));

        Assert.Contains("does not exist", ex.Message);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-4096)]
    public void Refuses_a_negative_offset(long offset)
    {
        var path = Fixture("trace.csv", 64);

        Assert.Throws<FileTransferException>(
            () => Sender().Read(new FileReadRequest(path, offset), CancellationToken.None));
    }

    [Fact]
    public void Refuses_an_offset_past_the_end()
    {
        var path = Fixture("trace.csv", 64);

        var ex = Assert.Throws<FileTransferException>(
            () => Sender().Read(new FileReadRequest(path, 65), CancellationToken.None));

        Assert.Contains("past the end", ex.Message);
    }

    [Fact]
    public void Reading_exactly_at_the_end_yields_an_empty_final_slice()
    {
        // The boundary a fetch loop hits when the file divides evenly into slices.
        var path = Fixture("trace.csv", 64);

        var result = Sender().Read(new FileReadRequest(path, 64), CancellationToken.None);

        Assert.Equal(0, result.Length);
        Assert.True(result.EndOfFile);
    }
}
