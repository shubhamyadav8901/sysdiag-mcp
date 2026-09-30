using System.Runtime.Versioning;
using Diag.Mcp.Server.Files;
using Microsoft.Extensions.Logging.Abstractions;

namespace Diag.Mcp.Server.Tests;

/// <summary>A path through a /proc magic link cannot be judged, so it is never owned.</summary>
/// <remarks>
/// readlink on <c>/proc/&lt;pid&gt;/root</c>, <c>cwd</c> or <c>fd/N</c> prints a path, but the kernel
/// never follows that name: it jumps straight to the object. For a process in a container that is the
/// container's root, and an absolute link met below it resolves against the server's own root again.
/// Judged by what readlink printed, <c>/proc/&lt;ctr&gt;/root/var/lib/linuxdiag/x</c> looked owned while
/// root wrote wherever the container's links pointed.
/// </remarks>
public sealed class ProcMagicLinkScopeTests : IDisposable
{
    private readonly string _root = Directory.CreateDirectory(
        Path.Combine(Path.GetTempPath(), $"diag-magic-{Guid.NewGuid():N}")).FullName;

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    private FileTransferOptions Options(bool arbitrary) => new(_root, arbitrary, arbitrary, "W=1", "R=1");

    // /proc/self/root is this process's own root, so the path below it is the artifact directory itself:
    // what the old check accepted as owned, and what a container's root would have made dangerous.
    private string ThroughProcRoot(string name) => "/proc/self/root" + Path.Combine(_root, name);

    [LinuxFact]
    [UnsupportedOSPlatform("windows")]
    public void A_write_through_a_proc_root_link_needs_arbitrary_write_even_when_readlink_says_it_is_owned()
    {
        var receiver = new FileReceiver(Options(arbitrary: false), NullLogger<FileReceiver>.Instance);

        var ex = Assert.Throws<FileTransferException>(() =>
            receiver.Receive(new FileWriteRequest(ThroughProcRoot("x.bin"), [1]), CancellationToken.None));

        Assert.Contains("W=1", ex.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(_root, "x.bin")));
    }

    [LinuxFact]
    [UnsupportedOSPlatform("windows")]
    public void A_read_through_a_proc_root_link_needs_arbitrary_read()
    {
        File.WriteAllBytes(Path.Combine(_root, "y.bin"), [1]);
        var sender = new FileSender(Options(arbitrary: false), NullLogger<FileSender>.Instance);

        var ex = Assert.Throws<FileTransferException>(() =>
            sender.Read(new FileReadRequest(ThroughProcRoot("y.bin")), CancellationToken.None));

        Assert.Contains("R=1", ex.Message, StringComparison.Ordinal);
    }

    [LinuxFact]
    [UnsupportedOSPlatform("windows")]
    public void A_read_through_an_open_descriptor_link_needs_arbitrary_read()
    {
        var path = Path.Combine(_root, "held.bin");
        File.WriteAllBytes(path, [1]);
        using var held = File.OpenHandle(path);

        var sender = new FileSender(Options(arbitrary: false), NullLogger<FileSender>.Instance);
        var ex = Assert.Throws<FileTransferException>(() =>
            sender.Read(new FileReadRequest($"/proc/self/fd/{held.DangerousGetHandle()}"), CancellationToken.None));

        Assert.Contains("R=1", ex.Message, StringComparison.Ordinal);
    }

    [LinuxFact]
    [UnsupportedOSPlatform("windows")]
    public void An_artifact_directory_configured_through_a_proc_root_link_owns_nothing_below_it()
    {
        // Past the magic link both sides are kept as spelled, so the path matches the configured
        // directory by prefix -- while a container's link below that point would still carry the
        // write back onto the host. Crossing one is what makes a path unowned, not its spelling.
        var options = new FileTransferOptions(ThroughProcRoot(""), false, false, "W=1", "R=1");
        var receiver = new FileReceiver(options, NullLogger<FileReceiver>.Instance);

        Assert.Throws<FileTransferException>(() =>
            receiver.Receive(new FileWriteRequest(ThroughProcRoot("w.bin"), [1]), CancellationToken.None));
        Assert.False(File.Exists(Path.Combine(_root, "w.bin")));
    }

    [LinuxFact]
    [UnsupportedOSPlatform("windows")]
    public void With_arbitrary_write_a_proc_root_path_is_still_written()
    {
        // Judged unowned, not refused: an operator who granted writing anywhere keeps reaching a
        // container's files, and a held-open deleted log through /proc/<pid>/fd.
        var receiver = new FileReceiver(Options(arbitrary: true), NullLogger<FileReceiver>.Instance);

        receiver.Receive(new FileWriteRequest(ThroughProcRoot("z.bin"), [7]), CancellationToken.None);

        Assert.Equal([7], File.ReadAllBytes(Path.Combine(_root, "z.bin")));
    }

    [LinuxFact]
    public void Proc_itself_is_recognised_as_procfs_and_an_ordinary_directory_is_not()
    {
        // Asked of the directory holding a link that exists, which is the only way the walk asks it.
        Assert.True(FileScope.IsOnProcfs("/proc/self"));
        Assert.False(FileScope.IsOnProcfs(_root));
    }

    [LinuxFact]
    [UnsupportedOSPlatform("windows")]
    public void An_ordinary_link_between_owned_directories_is_still_owned()
    {
        // The other side of the fix: only procfs links stop the judgement. Treating every link that way
        // would refuse, without a grant, a staging directory that happens to be reached through a link.
        var real = Directory.CreateDirectory(Path.Combine(_root, "real")).FullName;
        File.CreateSymbolicLink(Path.Combine(_root, "link"), real);
        var receiver = new FileReceiver(Options(arbitrary: false), NullLogger<FileReceiver>.Instance);

        receiver.Receive(new FileWriteRequest(Path.Combine(_root, "link", "f.bin"), [5]), CancellationToken.None);

        Assert.Equal([5], File.ReadAllBytes(Path.Combine(real, "f.bin")));
    }

    [Fact]
    public void The_walk_stops_judging_at_a_magic_link_and_keeps_the_rest_as_spelled()
    {
        // Every platform, through a fake: A\proc\1\root is a magic link whose readlink says "the root".
        var a = Path.Combine(Path.GetTempPath(), "magic-fake");
        var magic = Path.Combine(a, "proc", "1", "root");
        var requested = Path.Combine(magic, "owned", "x");

        var (real, crossesMagicLink) = FileScope.Walk(
            requested,
            path => path == magic ? Path.GetPathRoot(a) : null,
            relativeTargetsBySpelling: false,
            isMagicLink: path => path == magic);

        Assert.True(crossesMagicLink);
        Assert.Equal(requested, real);
    }
}
