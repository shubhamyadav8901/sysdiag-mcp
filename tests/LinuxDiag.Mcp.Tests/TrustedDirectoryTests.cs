using DiagRelay.Mcp.Tests;
using Diag.Mcp.Server.SelfUpdate;
using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Diagnostics.SelfUpdate;
using LinuxDiag.Mcp.Hosting;
using LinuxDiag.Mcp.Linux.Native;
using Microsoft.Extensions.Logging.Abstractions;

namespace LinuxDiag.Mcp.Tests;

/// <summary>
/// The artifact directory holds the script root runs for update_self and the log root writes, so no other
/// account may be able to write it, or replace it by writing a directory above it.
/// </summary>
/// <remarks>
/// Unix only: the cases are POSIX paths (/var/lib/linuxdiag) and Unix modes, which Windows turns into
/// D:\var\lib\... and refuses. The code is LinuxDiag's, which never runs on Windows; macOS and CI's Linux
/// jobs run them.
/// </remarks>
public sealed class TrustedDirectoryTests
{
    private const ushort Directory = 0x4000;
    private static readonly uint[] Root = [0];

    /// <summary>A hand-written file system: each entry's owner and mode, links included -- each with an owner of its own.</summary>
    /// <remarks>Answers as lstat and readlink do: a link is never followed here; the walk under test follows it.</remarks>
    private sealed class Tree
    {
        private const ushort SymbolicLink = 0xA000;

        private readonly Dictionary<string, FileStatus> _entries = new(StringComparer.Ordinal)
        {
            ["/"] = Dir(0, 0b111_101_101),
        };

        private readonly Dictionary<string, string> _links = new(StringComparer.Ordinal);

        public Tree With(string path, uint uid, int mode)
        {
            _entries[path] = Dir(uid, mode);
            return this;
        }

        public Tree Link(string link, string target, uint owner = 0)
        {
            _links[link] = target;
            _entries[link] = new FileStatus(owner, 0, SymbolicLink | 0b111_111_111, false, false);
            return this;
        }

        private static FileStatus Dir(uint uid, int mode) => new(uid, 0, (ushort)(Directory | mode), false, false);

        public FileStatus? LinkStatus(string path) => _entries.TryGetValue(path, out var status) ? status : null;

        public string? ReadLink(string path) => _links.GetValueOrDefault(path);

        public IReadOnlyList<string> Problems(string path, uint[]? trusted = null) =>
            TrustedDirectory.Problems(path, trusted ?? Root, LinkStatus, ReadLink);

        public IReadOnlyList<string> ProblemsBeforeCreating(string path) =>
            TrustedDirectory.ProblemsBeforeCreating(path, Root, LinkStatus, ReadLink);
    }

    [UnixFact]
    public void A_root_owned_0700_directory_under_root_owned_parents_passes()
    {
        var tree = new Tree().With("/var", 0, 0b111_101_101).With("/var/lib", 0, 0b111_101_101).With("/var/lib/linuxdiag", 0, 0b111_000_000);

        Assert.Empty(tree.Problems("/var/lib/linuxdiag"));
    }

    [UnixFact]
    public void A_shared_group_or_world_writable_artifact_directory_is_refused()
    {
        // Review: with --artifacts /srv/diag already 0777, a local user could rename root's self-update.sh away
        // between its creation and sh reading it, and drop in their own: root code execution at the next update.
        var tree = new Tree().With("/srv", 0, 0b111_101_101).With("/srv/diag", 0, 0b111_111_111).With("/srv/team", 0, 0b111_111_000);

        Assert.Contains(tree.Problems("/srv/diag"), p => p.Contains("/srv/diag is writable by its group or by everyone", StringComparison.Ordinal));
        Assert.Contains(tree.Problems("/srv/team"), p => p.Contains("/srv/team is writable", StringComparison.Ordinal));
    }

    [UnixFact]
    public void A_directory_another_account_owns_is_refused_even_at_0700()
    {
        // Review: /opt/linuxdiag pre-created by the operator's own account kept that owner, who could then
        // replace the binary a root service runs.
        var tree = new Tree().With("/opt", 0, 0b111_101_101).With("/opt/linuxdiag", 1000, 0b111_000_000);

        Assert.Contains(tree.Problems("/opt/linuxdiag"), p => p.Contains("owned by uid 1000", StringComparison.Ordinal));
    }

    [UnixFact]
    public void A_parent_another_account_can_write_is_refused_because_it_can_replace_the_directory()
    {
        var tree = new Tree().With("/srv", 0, 0b111_111_111).With("/srv/diag", 0, 0b111_000_000)
            .With("/home", 0, 0b111_101_101).With("/home/op", 1000, 0b111_101_101).With("/home/op/diag", 0, 0b111_000_000);

        Assert.Contains(tree.Problems("/srv/diag"), p => p.StartsWith("/srv is writable", StringComparison.Ordinal));
        Assert.Contains(tree.Problems("/home/op/diag"), p => p.StartsWith("/home/op is owned by uid 1000", StringComparison.Ordinal));
    }

    [UnixFact]
    public void A_root_only_directory_inside_sticky_tmp_passes_but_tmp_itself_does_not()
    {
        // The sticky bit stops another account renaming root's entry, so /tmp above is safe; /tmp as the
        // directory itself is shared by everyone.
        var tree = new Tree().With("/tmp", 0, 0b1_111_111_111).With("/tmp/diag", 0, 0b111_000_000);

        Assert.Empty(tree.Problems("/tmp/diag"));
        Assert.Contains(tree.Problems("/tmp"), p => p.Contains("shared sticky directory", StringComparison.Ordinal));
    }

    [UnixFact]
    public void A_link_is_judged_both_where_it_is_spelled_and_where_it_leads()
    {
        // /data/diag is root's alone, but the link to it sits in a directory anyone can write, so the link
        // itself can be replaced.
        var tree = new Tree().With("/data", 0, 0b111_101_101).With("/data/diag", 0, 0b111_000_000).With("/shared", 0, 0b111_111_111);
        tree.Link("/shared/diag", "/data/diag");

        Assert.Contains(tree.Problems("/shared/diag"), p => p.StartsWith("/shared is writable", StringComparison.Ordinal));
    }

    [UnixFact]
    public void A_link_another_account_owns_in_sticky_tmp_is_refused_even_though_it_leads_to_a_root_only_directory()
    {
        // Re-check: `ln -s /root /tmp/diag` as uid 1000, then --artifacts /tmp/diag. /tmp is sticky and /root is
        // root's 0700, so only where the link led was judged and it passed -- but the link is the user's, the sticky
        // bit lets its owner replace it, and they could repoint it between the check and root's sh opening the
        // script inside: root code execution.
        var tree = new Tree().With("/tmp", 0, 0b1_111_111_111).With("/root", 0, 0b111_000_000)
            .Link("/tmp/diag", "/root", owner: 1000).Link("/tmp/mine", "/root", owner: 0);

        Assert.Contains(tree.Problems("/tmp/diag"), p => p.StartsWith(
            "/tmp/diag is a link owned by uid 1000, not root, in the shared sticky directory /tmp", StringComparison.Ordinal));
        Assert.Contains(tree.ProblemsBeforeCreating("/tmp/diag/new"), p => p.StartsWith("/tmp/diag is a link owned by uid 1000", StringComparison.Ordinal));
        Assert.Empty(tree.Problems("/tmp/mine"));
    }

    [UnixFact]
    public void A_link_met_halfway_is_judged_though_it_is_neither_the_path_as_written_nor_where_it_ends()
    {
        // realpath plus the spelling saw /, /opt and /root here, never /tmp/y or /shared/y in between.
        var tree = new Tree().With("/opt", 0, 0b111_101_101).With("/tmp", 0, 0b1_111_111_111).With("/root", 0, 0b111_000_000)
            .With("/shared", 0, 0b111_111_111)
            .Link("/opt/x", "/tmp/y").Link("/tmp/y", "/root", owner: 1000)
            .Link("/opt/z", "../shared/y").Link("/shared/y", "/root");

        Assert.Contains(tree.Problems("/opt/x"), p => p.StartsWith("/tmp/y is a link owned by uid 1000", StringComparison.Ordinal));
        Assert.Contains(tree.Problems("/opt/z"), p => p.StartsWith("/shared is writable", StringComparison.Ordinal));
    }

    [UnixFact]
    public void Dot_dot_after_a_link_is_taken_from_where_the_link_led_not_from_its_spelling()
    {
        // /safe/l/../diag is /data/diag to the kernel; folded by spelling it was /safe/diag, which is not what root uses.
        var tree = new Tree().With("/safe", 0, 0b111_101_101).With("/safe/diag", 0, 0b111_000_000)
            .With("/data", 0, 0b111_111_111).With("/data/sub", 0, 0b111_101_101).With("/data/diag", 0, 0b111_000_000)
            .Link("/safe/l", "/data/sub");

        Assert.Empty(tree.Problems("/safe/diag"));
        Assert.Contains(tree.Problems("/safe/l/../diag"), p => p.StartsWith("/data is writable", StringComparison.Ordinal));
    }

    [UnixFact]
    public void A_link_loop_is_a_problem_not_a_hang()
    {
        var tree = new Tree().Link("/a", "/b").Link("/b", "/a");

        Assert.Contains(tree.Problems("/a/diag"), p => p.Contains("a loop", StringComparison.Ordinal));
    }

    [UnixFact]
    public void A_directory_that_does_not_exist_or_is_not_a_directory_is_a_problem()
    {
        var tree = new Tree();

        Assert.Contains(tree.Problems("/nowhere"), p => p.Contains("does not exist", StringComparison.Ordinal));
    }

    [UnixFact]
    public void A_directory_not_yet_made_is_judged_by_the_directories_it_would_be_made_in()
    {
        // Review: --artifacts /srv/team/diag was created first and checked after, so a refusal left a new root
        // directory behind under the very parent it refused. What the new directory would sit in is judged first.
        var tree = new Tree().With("/srv", 0, 0b111_101_101).With("/srv/team", 0, 0b111_111_000)
            .With("/var", 0, 0b111_101_101).With("/var/lib", 0, 0b111_101_101)
            .With("/tmp", 0, 0b1_111_111_111).With("/data", 0, 0b111_101_101).With("/shared", 0, 0b111_111_111);
        tree.Link("/var/data", "/shared");

        Assert.Contains(tree.ProblemsBeforeCreating("/srv/team/diag/a"), p => p.StartsWith("/srv/team is writable", StringComparison.Ordinal));
        Assert.Contains(tree.ProblemsBeforeCreating("/var/data/diag"), p => p.StartsWith("/shared is writable", StringComparison.Ordinal));
        Assert.Empty(tree.ProblemsBeforeCreating("/var/lib/new/diag"));
        Assert.Empty(tree.ProblemsBeforeCreating("/tmp/diag"));
    }

    [UnixFact]
    public void An_unprivileged_server_may_own_its_own_directory()
    {
        var tree = new Tree().With("/home", 0, 0b111_101_101).With("/home/me", 1000, 0b111_101_101).With("/home/me/diag", 1000, 0b111_000_000);

        Assert.Empty(tree.Problems("/home/me/diag", [0, 1000]));
        Assert.NotEmpty(tree.Problems("/home/me/diag", [0, 1001]));
    }

    [UnixFact]
    public void Update_self_refuses_to_write_its_root_script_into_a_directory_another_account_controls()
    {
        // The installer's check is not enough on its own: a later chmod, or an env file pointed elsewhere,
        // reopens the hole. So the helper checks again, before it writes anything.
        var artifacts = System.IO.Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld-tr-{Guid.NewGuid():N}")).FullName;
        try
        {
            var helper = new SystemdRestartHelper(
                new LinuxDiagOptions { ArtifactDirectory = artifacts, ServiceName = null }, NullLogger<SystemdRestartHelper>.Instance)
            {
                DirectoryProblems = _ => ["/srv is writable by its group or by everyone."],
            };

            var ex = Assert.Throws<SelfUpdateRejectedException>(() => helper.Launch(
                "/opt/linuxdiag/LinuxDiag.Mcp", "/opt/linuxdiag/LinuxDiag.Mcp.new", "ABC", Path.Combine(artifacts, "self-update.log")));

            Assert.Contains("/srv is writable", ex.Message, StringComparison.Ordinal);
            Assert.Contains("Nothing has been changed", ex.Message, StringComparison.Ordinal);
            Assert.False(File.Exists(Path.Combine(artifacts, "self-update.sh")), "no script may be written");
        }
        finally
        {
            System.IO.Directory.Delete(artifacts, recursive: true);
        }
    }

    [UnprivilegedLinuxFact]
    public void The_installer_refuses_an_existing_artifact_directory_that_is_world_writable_or_not_roots()
    {
        // Through the real statx: a 0777 directory, and one owned by this (non-root) test account.
        var parent = System.IO.Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld-art-{Guid.NewGuid():N}")).FullName;
        try
        {
            var open = System.IO.Directory.CreateDirectory(Path.Combine(parent, "open")).FullName;
            File.SetUnixFileMode(open, (UnixFileMode)0b111_111_111);
            var mine = System.IO.Directory.CreateDirectory(Path.Combine(parent, "mine"), (UnixFileMode)0b111_000_000).FullName;

            var openEx = Assert.Throws<ConfigurationException>(() => LinuxServiceInstaller.ArtifactDirectory(open));
            var mineEx = Assert.Throws<ConfigurationException>(() => LinuxServiceInstaller.ArtifactDirectory(mine));

            Assert.Contains("writable by its group or by everyone", openEx.Message, StringComparison.Ordinal);
            Assert.Contains($"owned by uid {LibC.EffectiveUserId()}", mineEx.Message, StringComparison.Ordinal);
            Assert.Contains("Choose a directory only root can write", mineEx.Message, StringComparison.Ordinal);
        }
        finally
        {
            System.IO.Directory.Delete(parent, recursive: true);
        }
    }

    [UnprivilegedLinuxFact]
    public void The_installer_refuses_an_artifact_directory_it_would_create_under_another_accounts_directory_without_creating_it()
    {
        var parent = System.IO.Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld-new-{Guid.NewGuid():N}")).FullName;
        try
        {
            var requested = Path.Combine(parent, "diag", "artifacts");

            var ex = Assert.Throws<ConfigurationException>(() => LinuxServiceInstaller.ArtifactDirectory(requested));

            Assert.Contains($"{parent} is owned by uid {LibC.EffectiveUserId()}", ex.Message, StringComparison.Ordinal);
            Assert.Contains("Nothing was installed", ex.Message, StringComparison.Ordinal);
            Assert.False(System.IO.Directory.Exists(Path.Combine(parent, "diag")), "a refused --artifacts must leave nothing behind");
        }
        finally
        {
            System.IO.Directory.Delete(parent, recursive: true);
        }
    }

    [UnprivilegedLinuxFact]
    public void The_real_check_reads_a_links_own_owner_in_sticky_tmp_not_its_targets()
    {
        // Through the real lstat: a link this (non-root) account makes in /tmp to root's /usr. Following it, as
        // stat does, saw only root's directory.
        var link = Path.Combine("/tmp", $"ld-link-{Guid.NewGuid():N}");
        File.CreateSymbolicLink(link, "/usr");
        try
        {
            Assert.Contains(TrustedDirectory.Problems(link, Root),
                p => p.StartsWith($"{link} is a link owned by uid {LibC.EffectiveUserId()}", StringComparison.Ordinal));
            Assert.Empty(TrustedDirectory.Problems("/usr", Root));
        }
        finally
        {
            File.Delete(link);
        }
    }

    [LinuxFact]
    public void The_real_check_passes_a_root_owned_system_directory_and_flags_a_world_writable_one()
    {
        Assert.Empty(TrustedDirectory.Problems("/usr/bin", Root));

        var open = System.IO.Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld-ww-{Guid.NewGuid():N}")).FullName;
        try
        {
            File.SetUnixFileMode(open, (UnixFileMode)0b111_111_111);
            Assert.Contains(TrustedDirectory.Problems(open, [0, LibC.EffectiveUserId()]),
                p => p.Contains("writable by its group or by everyone", StringComparison.Ordinal));
        }
        finally
        {
            System.IO.Directory.Delete(open, recursive: true);
        }
    }
}
