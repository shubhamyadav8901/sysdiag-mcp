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
public sealed class TrustedDirectoryTests
{
    private const ushort Directory = 0x4000;
    private static readonly uint[] Root = [0];

    /// <summary>A hand-written file system: each path's owner and mode, and the links between paths.</summary>
    private sealed class Tree
    {
        private readonly Dictionary<string, FileStatus> _entries = new(StringComparer.Ordinal)
        {
            ["/"] = Dir(0, 0b111_101_101),
        };

        public Dictionary<string, string> Links { get; } = new(StringComparer.Ordinal);

        public Tree With(string path, uint uid, int mode)
        {
            _entries[path] = Dir(uid, mode);
            return this;
        }

        private static FileStatus Dir(uint uid, int mode) => new(uid, 0, (ushort)(Directory | mode), false, false);

        public FileStatus? Status(string path) => _entries.TryGetValue(RealPath(path) ?? path, out var status) ? status : null;

        public string? RealPath(string path)
        {
            foreach (var (link, target) in Links)
            {
                if (path == link || path.StartsWith(link + "/", StringComparison.Ordinal))
                {
                    path = target + path[link.Length..];
                }
            }

            return _entries.ContainsKey(path) ? path : null;
        }

        public IReadOnlyList<string> Problems(string path, uint[]? trusted = null) =>
            TrustedDirectory.Problems(path, trusted ?? Root, Status, RealPath);

        public IReadOnlyList<string> ProblemsBeforeCreating(string path) =>
            TrustedDirectory.ProblemsBeforeCreating(path, Root, Status, RealPath);
    }

    [Fact]
    public void A_root_owned_0700_directory_under_root_owned_parents_passes()
    {
        var tree = new Tree().With("/var", 0, 0b111_101_101).With("/var/lib", 0, 0b111_101_101).With("/var/lib/linuxdiag", 0, 0b111_000_000);

        Assert.Empty(tree.Problems("/var/lib/linuxdiag"));
    }

    [Fact]
    public void A_shared_group_or_world_writable_artifact_directory_is_refused()
    {
        // Review: with --artifacts /srv/diag already 0777, a local user could rename root's self-update.sh away
        // between its creation and sh reading it, and drop in their own: root code execution at the next update.
        var tree = new Tree().With("/srv", 0, 0b111_101_101).With("/srv/diag", 0, 0b111_111_111).With("/srv/team", 0, 0b111_111_000);

        Assert.Contains(tree.Problems("/srv/diag"), p => p.Contains("/srv/diag is writable by its group or by everyone", StringComparison.Ordinal));
        Assert.Contains(tree.Problems("/srv/team"), p => p.Contains("/srv/team is writable", StringComparison.Ordinal));
    }

    [Fact]
    public void A_directory_another_account_owns_is_refused_even_at_0700()
    {
        // Review: /opt/linuxdiag pre-created by the operator's own account kept that owner, who could then
        // replace the binary a root service runs.
        var tree = new Tree().With("/opt", 0, 0b111_101_101).With("/opt/linuxdiag", 1000, 0b111_000_000);

        Assert.Contains(tree.Problems("/opt/linuxdiag"), p => p.Contains("owned by uid 1000", StringComparison.Ordinal));
    }

    [Fact]
    public void A_parent_another_account_can_write_is_refused_because_it_can_replace_the_directory()
    {
        var tree = new Tree().With("/srv", 0, 0b111_111_111).With("/srv/diag", 0, 0b111_000_000)
            .With("/home", 0, 0b111_101_101).With("/home/op", 1000, 0b111_101_101).With("/home/op/diag", 0, 0b111_000_000);

        Assert.Contains(tree.Problems("/srv/diag"), p => p.StartsWith("/srv is writable", StringComparison.Ordinal));
        Assert.Contains(tree.Problems("/home/op/diag"), p => p.StartsWith("/home/op is owned by uid 1000", StringComparison.Ordinal));
    }

    [Fact]
    public void A_root_only_directory_inside_sticky_tmp_passes_but_tmp_itself_does_not()
    {
        // The sticky bit stops another account renaming root's entry, so /tmp above is safe; /tmp as the
        // directory itself is shared by everyone.
        var tree = new Tree().With("/tmp", 0, 0b1_111_111_111).With("/tmp/diag", 0, 0b111_000_000);

        Assert.Empty(tree.Problems("/tmp/diag"));
        Assert.Contains(tree.Problems("/tmp"), p => p.Contains("shared sticky directory", StringComparison.Ordinal));
    }

    [Fact]
    public void A_link_is_judged_both_where_it_is_spelled_and_where_it_leads()
    {
        // /data/diag is root's alone, but the link to it sits in a directory anyone can write, so the link
        // itself can be replaced.
        var tree = new Tree().With("/data", 0, 0b111_101_101).With("/data/diag", 0, 0b111_000_000).With("/shared", 0, 0b111_111_111);
        tree.Links["/shared/diag"] = "/data/diag";

        Assert.Contains(tree.Problems("/shared/diag"), p => p.StartsWith("/shared is writable", StringComparison.Ordinal));
    }

    [Fact]
    public void A_directory_that_does_not_exist_or_is_not_a_directory_is_a_problem()
    {
        var tree = new Tree();

        Assert.Contains(tree.Problems("/nowhere"), p => p.Contains("does not exist", StringComparison.Ordinal));
    }

    [Fact]
    public void A_directory_not_yet_made_is_judged_by_the_directories_it_would_be_made_in()
    {
        // Review: --artifacts /srv/team/diag was created first and checked after, so a refusal left a new root
        // directory behind under the very parent it refused. What the new directory would sit in is judged first.
        var tree = new Tree().With("/srv", 0, 0b111_101_101).With("/srv/team", 0, 0b111_111_000)
            .With("/var", 0, 0b111_101_101).With("/var/lib", 0, 0b111_101_101)
            .With("/tmp", 0, 0b1_111_111_111).With("/data", 0, 0b111_101_101).With("/shared", 0, 0b111_111_111);
        tree.Links["/var/data"] = "/shared";

        Assert.Contains(tree.ProblemsBeforeCreating("/srv/team/diag/a"), p => p.StartsWith("/srv/team is writable", StringComparison.Ordinal));
        Assert.Contains(tree.ProblemsBeforeCreating("/var/data/diag"), p => p.StartsWith("/shared is writable", StringComparison.Ordinal));
        Assert.Empty(tree.ProblemsBeforeCreating("/var/lib/new/diag"));
        Assert.Empty(tree.ProblemsBeforeCreating("/tmp/diag"));
    }

    [Fact]
    public void An_unprivileged_server_may_own_its_own_directory()
    {
        var tree = new Tree().With("/home", 0, 0b111_101_101).With("/home/me", 1000, 0b111_101_101).With("/home/me/diag", 1000, 0b111_000_000);

        Assert.Empty(tree.Problems("/home/me/diag", [0, 1000]));
        Assert.NotEmpty(tree.Problems("/home/me/diag", [0, 1001]));
    }

    [Fact]
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

    [LinuxFact]
    public void The_real_check_passes_a_root_owned_system_directory_and_flags_a_world_writable_one()
    {
        Assert.Empty(TrustedDirectory.Problems("/usr/bin", Root, LibC.Status, LibC.RealPath));

        var open = System.IO.Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld-ww-{Guid.NewGuid():N}")).FullName;
        try
        {
            File.SetUnixFileMode(open, (UnixFileMode)0b111_111_111);
            Assert.Contains(TrustedDirectory.Problems(open, [0, LibC.EffectiveUserId()], LibC.Status, LibC.RealPath),
                p => p.Contains("writable by its group or by everyone", StringComparison.Ordinal));
        }
        finally
        {
            System.IO.Directory.Delete(open, recursive: true);
        }
    }
}
