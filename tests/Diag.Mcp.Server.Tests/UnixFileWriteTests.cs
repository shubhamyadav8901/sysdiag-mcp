using System.Runtime.Versioning;
using Diag.Mcp.Server.Files;
using Microsoft.Extensions.Logging.Abstractions;

namespace Diag.Mcp.Server.Tests;

/// <summary>The receiver's write path off Windows: owner-only, and never through a link.</summary>
/// <remarks>
/// On Windows the path is unchanged and these report Skipped. On Linux a root service writes into a
/// directory a caller named, and following a planted link or keeping a loose mode there is how a
/// transfer turns into an overwrite of someone else's file, or a readable one.
/// </remarks>
public sealed class UnixFileWriteTests : IDisposable
{
    private const UnixFileMode OwnerReadWrite = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private readonly string _root = Directory.CreateDirectory(
        Path.Combine(Path.GetTempPath(), $"diag-kit-{Guid.NewGuid():N}")).FullName;

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    private FileReceiver Receiver() => new(
        new FileTransferOptions(_root, false, false, "X=1", "Y=1"), NullLogger<FileReceiver>.Instance);

    [UnixFact]
    [UnsupportedOSPlatform("windows")]
    public void A_written_file_and_the_directory_made_for_it_are_owner_only()
    {
        var path = Path.Combine(_root, "made", "a.bin");

        Receiver().Receive(new FileWriteRequest(path, [1, 2, 3]), CancellationToken.None);

        Assert.Equal(OwnerReadWrite, File.GetUnixFileMode(path));
        Assert.Equal(OwnerReadWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(Path.GetDirectoryName(path)!));
    }

    [UnixFact]
    [UnsupportedOSPlatform("windows")]
    public void Overwriting_a_loose_file_leaves_it_owner_only()
    {
        // Review Focus 4: replacing an existing 0644 file must not inherit its mode.
        var path = Path.Combine(_root, "loose.bin");
        File.WriteAllBytes(path, [0]);
        File.SetUnixFileMode(path, OwnerReadWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        Receiver().Receive(new FileWriteRequest(path, [1, 2]), CancellationToken.None);

        Assert.Equal(OwnerReadWrite, File.GetUnixFileMode(path));
    }

    [UnixFact]
    [UnsupportedOSPlatform("windows")]
    public void An_append_that_creates_the_file_creates_it_owner_only()
    {
        // An append to a missing path creates it -- a resumed transfer whose partial file was removed,
        // or a caller that starts with append. Created with the process umask, that is 0644 on a root
        // service: every chunk readable by every local account.
        var path = Path.Combine(_root, "appended.bin");

        Receiver().Receive(new FileWriteRequest(path, [1], Append: true), CancellationToken.None);

        Assert.Equal(OwnerReadWrite, File.GetUnixFileMode(path));
    }

    [UnixFact]
    public void A_symlink_at_the_destination_is_replaced_not_followed()
    {
        var victim = Path.Combine(_root, "victim.txt");
        File.WriteAllText(victim, "not yours");
        var path = Path.Combine(_root, "dest.bin");
        File.CreateSymbolicLink(path, victim);

        Receiver().Receive(new FileWriteRequest(path, [7, 7]), CancellationToken.None);

        Assert.Equal("not yours", File.ReadAllText(victim));
        Assert.Null(new FileInfo(path).LinkTarget);
    }

    [UnixFact]
    public void An_append_to_a_path_that_became_a_symlink_is_refused()
    {
        // Review Focus 3: every chunk after the first appends, and a link swapped in between chunks
        // must not be followed.
        var victim = Path.Combine(_root, "victim.txt");
        File.WriteAllText(victim, "not yours");
        var path = Path.Combine(_root, "chunked.bin");
        File.CreateSymbolicLink(path, victim);

        Assert.Throws<FileTransferException>(() => Receiver().Receive(
            new FileWriteRequest(path, [1], Append: true), CancellationToken.None));
        Assert.Equal("not yours", File.ReadAllText(victim));
    }
}
