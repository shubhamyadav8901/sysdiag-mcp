using System.Diagnostics;
using DiagRelay.Mcp.Tests;
using LinuxDiag.Mcp.Diagnostics.SelfUpdate;
using LinuxDiag.Mcp.Hosting;
using LinuxDiag.Mcp.Linux.Native;

namespace LinuxDiag.Mcp.Tests;

/// <summary>
/// The installer's own directories -- /opt/linuxdiag, /etc/linuxdiag, /var/lib/linuxdiag -- are taken over whole when
/// they already exist: what another account left inside must not keep that account's hold on a root service.
/// </summary>
/// <remarks>Unix only: POSIX paths and modes, which Windows turns into drive paths and refuses.</remarks>
public sealed class OwnedDirectoryTests
{
    private const ushort Directory = 0x4000;
    private const ushort Regular = 0x8000;
    private const ushort SymbolicLink = 0xA000;
    private const ushort Fifo = 0x1000;

    /// <summary>A hand-written directory tree, answering as lstat does, that records every takeover.</summary>
    private sealed class Tree
    {
        private readonly Dictionary<string, FileStatus> _entries = new(StringComparer.Ordinal);

        public List<(string Path, UnixFileMode Mode)> TakenOver { get; } = [];

        public Tree With(string path, ushort type, uint uid, int mode, uint links = 1)
        {
            _entries[path] = new FileStatus(uid, uid, (ushort)(type | mode), false, false, links);
            return this;
        }

        public FileStatus? LinkStatus(string path) => _entries.TryGetValue(path, out var status) ? status : null;

        public IEnumerable<string> Entries(string directory) =>
            _entries.Keys.Where(p => p.StartsWith(directory + "/", StringComparison.Ordinal) && !p[(directory.Length + 1)..].Contains('/'));

        public IReadOnlyList<string> TakeOver(string directory) =>
            LinuxServiceInstaller.TakeOverContents(directory, LinkStatus, Entries, (path, mode) => TakenOver.Add((path, mode)));
    }

    [UnixFact]
    public void What_another_account_left_inside_is_made_roots_and_writable_by_root_alone()
    {
        // Re-check: only /opt/linuxdiag itself was chowned. A file left inside stayed its old owner's to rewrite --
        // in the directory a root service runs from and reads staged builds out of.
        var tree = new Tree()
            .With("/opt/linuxdiag/LinuxDiag.Mcp", Regular, 1000, 0b111_111_101)
            .With("/opt/linuxdiag/tool", Regular, 1000, 0b110_111_101_101)
            .With("/opt/linuxdiag/sub", Directory, 1000, 0b111_111_111)
            .With("/opt/linuxdiag/sub/notes", Regular, 1000, 0b110_110_110);

        Assert.Empty(tree.TakeOver("/opt/linuxdiag"));

        Assert.Equal(
            [
                ("/opt/linuxdiag/LinuxDiag.Mcp", (UnixFileMode)0b111_101_101),
                ("/opt/linuxdiag/sub", (UnixFileMode)0b111_101_101),
                ("/opt/linuxdiag/sub/notes", (UnixFileMode)0b110_100_100),
                ("/opt/linuxdiag/tool", (UnixFileMode)0b111_101_101),
            ],
            tree.TakenOver);
    }

    [UnixFact]
    public void A_link_a_hard_link_or_a_fifo_inside_is_refused_and_never_taken_over()
    {
        // Re-check: self-update.log left as a link to /etc/shadow kept pointing there after the takeover, and root's
        // helper truncated the target. Chowning a hard link to /etc/shadow would have changed /etc/shadow itself.
        var tree = new Tree()
            .With("/var/lib/linuxdiag/self-update.log", SymbolicLink, 1000, 0b111_111_111)
            .With("/var/lib/linuxdiag/dump", Regular, 0, 0b110_100_000, links: 2)
            .With("/var/lib/linuxdiag/pipe", Fifo, 1000, 0b110_110_110)
            .With("/var/lib/linuxdiag/d", Directory, 1000, 0b111_000_000)
            .With("/var/lib/linuxdiag/d/deeper", SymbolicLink, 0, 0b111_111_111);

        var refused = tree.TakeOver("/var/lib/linuxdiag");

        Assert.Equal(4, refused.Count);
        Assert.Contains("/var/lib/linuxdiag/self-update.log is a symbolic link.", refused);
        Assert.Contains("/var/lib/linuxdiag/d/deeper is a symbolic link.", refused);
        Assert.Contains(refused, r => r.StartsWith("/var/lib/linuxdiag/dump has 1 other name", StringComparison.Ordinal));
        Assert.Contains(refused, r => r.StartsWith("/var/lib/linuxdiag/pipe is not a file or directory", StringComparison.Ordinal));
        Assert.Equal([("/var/lib/linuxdiag/d", (UnixFileMode)0b111_000_000)], tree.TakenOver);
    }

    [UnixFact]
    public void A_reinstall_over_roots_own_files_changes_nothing()
    {
        var tree = new Tree()
            .With("/opt/linuxdiag/LinuxDiag.Mcp", Regular, 0, 0b111_101_101)
            .With("/etc/linuxdiag/x.env", Regular, 0, 0b110_000_000);

        Assert.Empty(tree.TakeOver("/opt/linuxdiag"));
        Assert.Empty(tree.TakeOver("/etc/linuxdiag"));
        Assert.Empty(tree.TakenOver);
    }

    [LinuxFact]
    public void The_real_lstat_sees_a_planted_link_and_a_hard_link_and_takes_over_the_rest()
    {
        var root = System.IO.Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld-own-{Guid.NewGuid():N}")).FullName;
        try
        {
            var victim = Path.Combine(root, "victim");
            File.WriteAllText(victim, "keep");
            var inside = System.IO.Directory.CreateDirectory(Path.Combine(root, "linuxdiag")).FullName;
            File.CreateSymbolicLink(Path.Combine(inside, "self-update.log"), victim);
            // .NET has no hard link API; ln(1) makes one.
            using (var ln = Process.Start(new ProcessStartInfo("ln", [victim, Path.Combine(inside, "linked")]))!)
            {
                ln.WaitForExit();
                Assert.Equal(0, ln.ExitCode);
            }

            var plain = Path.Combine(inside, "plain");
            File.WriteAllText(plain, "x");
            File.SetUnixFileMode(plain, (UnixFileMode)0b110_110_110);

            var taken = new List<(string, UnixFileMode)>();
            var refused = LinuxServiceInstaller.TakeOverContents(
                inside, LibC.LinkStatus, System.IO.Directory.EnumerateFileSystemEntries, (p, m) => taken.Add((p, m)));

            Assert.Equal(2, refused.Count);
            Assert.Contains(refused, r => r.StartsWith(Path.Combine(inside, "self-update.log") + " is a symbolic link", StringComparison.Ordinal));
            Assert.Contains(refused, r => r.StartsWith(Path.Combine(inside, "linked") + " has 1 other name", StringComparison.Ordinal));
            Assert.Equal([(plain, (UnixFileMode)0b110_100_100)], taken);
        }
        finally
        {
            System.IO.Directory.Delete(root, recursive: true);
        }
    }

    [UnixFact]
    public void The_update_helper_removes_a_link_at_the_log_path_rather_than_writing_through_it()
    {
        // Re-check: `echo ... > "$log"` as root followed whatever was at the log's name. The script is run here for
        // real, against a process that has already exited, so it reaches its hash check and aborts with exit 2.
        var root = System.IO.Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld-log-{Guid.NewGuid():N}")).FullName;
        try
        {
            var victim = Path.Combine(root, "victim");
            File.WriteAllText(victim, "keep");
            var log = Path.Combine(root, "self-update.log");
            File.CreateSymbolicLink(log, victim);

            using var gone = Process.Start(new ProcessStartInfo("/bin/sh", ["-c", "exit 0"]))!;
            gone.WaitForExit();
            var script = Path.Combine(root, "self-update.sh");
            File.WriteAllText(script, SystemdRestartHelper.Script(
                gone.Id, Path.Combine(root, "live"), Path.Combine(root, "missing.new"), "ABC", log, "true"));

            using var run = Process.Start(new ProcessStartInfo("/bin/sh", [script]) { RedirectStandardError = true })!;
            run.WaitForExit();

            Assert.Equal(2, run.ExitCode);
            Assert.Equal("keep", File.ReadAllText(victim));
            Assert.Null(new FileInfo(log).LinkTarget);
            Assert.Contains("ABORT hash mismatch", File.ReadAllText(log), StringComparison.Ordinal);
        }
        finally
        {
            System.IO.Directory.Delete(root, recursive: true);
        }
    }
}
