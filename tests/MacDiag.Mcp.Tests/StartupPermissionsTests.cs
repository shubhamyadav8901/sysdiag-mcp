using System.Runtime.Versioning;
using MacDiag.Mcp.Hosting;
using static MacDiag.Mcp.Hosting.StartupPermissions;

namespace MacDiag.Mcp.Tests;

public sealed class StartupPermissionsTests
{
    private const string Env = "/etc/macdiag/macdiag.env";
    private const string Exe = "/Library/PrivilegedHelperTools/com.sysdiag.macdiag/MacDiag.Mcp";

    private static StatEntry Dir(string path, int mode, int uid = 0) => new(path, uid, mode, EntryKind.Directory);

    private static StatEntry File(string path, int mode, int uid = 0) => new(path, uid, mode, EntryKind.File);

    [Fact]
    public void A_root_owned_0600_env_file_under_root_only_directories_passes()
    {
        Assert.Empty(Problems(
        [
            Dir("/", 0b111_101_101), Dir("/private", 0b111_101_101), Dir("/private/etc", 0b111_101_101),
            new StatEntry("/etc", 0, 0b111_101_101, EntryKind.Link),
            Dir("/etc/macdiag", 0b111_000_000), File(Env, 0b110_000_000),
            File(Exe, 0b111_101_101),
        ], Env, Exe));
    }

    [Fact]
    public void An_env_file_readable_by_others_or_not_owned_by_root_is_named()
    {
        // Review Focus 1.
        var problems = Problems([Dir("/etc/macdiag", 0b111_000_000), File(Env, 0b110_100_100, uid: 501)], Env, null);

        Assert.Contains(problems, p => p.StartsWith(Env, StringComparison.Ordinal) && p.Contains("owned by uid 501", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.StartsWith(Env, StringComparison.Ordinal) && p.Contains("0644", StringComparison.Ordinal));
    }

    [Fact]
    public void An_env_file_that_is_a_link_is_refused_whatever_it_points_at()
    {
        var problems = Problems([Dir("/etc/macdiag", 0b111_000_000), new StatEntry(Env, 0, 0b111_101_101, EntryKind.Link)], Env, null);

        Assert.Contains(problems, p => p.StartsWith(Env, StringComparison.Ordinal) && p.Contains("symbolic link", StringComparison.Ordinal));
    }

    [Fact]
    public void An_ancestor_directory_writable_by_a_group_or_by_everyone_or_owned_by_another_account_is_named()
    {
        // Homebrew on Intel hands /usr/local/etc to the installing user: renaming a directory under it plants a config.
        var problems = Problems(
        [
            Dir("/usr/local", 0b111_111_101), Dir("/usr/local/etc", 0b111_101_101, uid: 501),
            File("/usr/local/etc/macdiag.env", 0b110_000_000),
        ], "/usr/local/etc/macdiag.env", null);

        Assert.Contains(problems, p => p.StartsWith("/usr/local ", StringComparison.Ordinal) && p.Contains("group", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.StartsWith("/usr/local/etc ", StringComparison.Ordinal) && p.Contains("uid 501", StringComparison.Ordinal));
    }

    [Fact]
    public void A_binary_another_account_can_write_is_named()
    {
        var problems = Problems([File(Env, 0b110_000_000), File(Exe, 0b111_111_101)], Env, Exe);

        Assert.Contains(problems, p => p.StartsWith(Exe, StringComparison.Ordinal));
    }

    [Fact]
    public void Stat_output_gives_uid_mode_kind_and_a_name_that_may_hold_spaces()
    {
        // stat -f "%u %Lp %HT %N" prints uid, octal permissions, file type and name.
        var entries = ParseStat("0 755 Directory /etc dir\n0 600 Regular File /etc/macdiag/macdiag.env\n0 755 Symbolic Link /etc\n0 644 Socket /var/run/x\n");

        Assert.Equal(new StatEntry("/etc dir", 0, 0b111_101_101, EntryKind.Directory), entries[0]);
        Assert.Equal(new StatEntry(Env, 0, 0b110_000_000, EntryKind.File), entries[1]);
        Assert.Equal(new StatEntry("/etc", 0, 0b111_101_101, EntryKind.Link), entries[2]);
        Assert.Equal(EntryKind.Other, entries[3].Kind);
    }

    [Fact]
    public void A_sticky_directory_reads_with_its_sticky_bit_so_the_artifact_check_refuses_it()
    {
        // stat -f "%Mp%Lp" prints /private/tmp as 1777; %Lp alone would say 777 and lose the sticky bit.
        var tmp = Assert.Single(ParseStat("0 1777 Directory /private/tmp\n"));

        Assert.Equal(0b1_111_111_111, tmp.Mode);
        Assert.Contains("sticky", Assert.Single(RootOnlyDirectoryProblems([tmp], "/private/tmp")), StringComparison.Ordinal);
    }

    [Fact]
    public void Every_ancestor_is_checked_root_first()
    {
        Assert.Equal(["/", "/etc", "/etc/macdiag", Env], Chain(Env));
    }

    [UnixFact]
    [UnsupportedOSPlatform("windows")]
    public void The_real_path_follows_links_in_every_component_so_their_targets_are_checked_too()
    {
        // /etc is a link to private/etc on macOS: checking only the spelled chain would examine the link and never
        // the directory the file is really in.
        // The temp directory is itself behind a link on a Mac (/var/folders is /private/var/folders), so the expected
        // path starts from its resolved spelling; only the link this test makes is then left for RealPath to follow.
        var created = Directory.CreateTempSubdirectory("perm-").FullName;
        var root = RealPath(created);
        try
        {
            var real = Directory.CreateDirectory(Path.Combine(root, "private", "etc")).FullName;
            Directory.CreateSymbolicLink(Path.Combine(root, "etc"), "private/etc");
            System.IO.File.WriteAllText(Path.Combine(real, "x.env"), "");

            Assert.Equal(Path.Combine(real, "x.env"), RealPath(Path.Combine(root, "etc", "x.env")));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [MacFact]
    [SupportedOSPlatform("macos")]
    public void A_directory_not_yet_created_is_judged_by_the_directories_above_it_and_refused_under_ones_another_account_owns()
    {
        // Before: a new --artifacts directory was created and never checked at all. The test's temp directory belongs to
        // the account running it, never root, so a directory to be made inside it must be refused before it exists.
        var mine = Directory.CreateTempSubdirectory("artifacts-").FullName;
        try
        {
            var wanted = Path.Combine(mine, "new", "deeper");

            var refused = Assert.Throws<ConfigurationException>(() => RequireRootOnlyDirectory(wanted, "--artifacts"));

            Assert.Contains($"{RealPath(mine)} is owned by uid ", refused.Message, StringComparison.Ordinal);
            Assert.False(Directory.Exists(Path.Combine(mine, "new")));
        }
        finally
        {
            Directory.Delete(mine, recursive: true);
        }
    }

    [MacFact]
    [SupportedOSPlatform("macos")]
    public void A_directory_not_yet_created_under_root_only_directories_passes_and_is_not_made_by_the_check()
    {
        // /var is a link to private/var, and /private/var/db is root's 0755 on every Mac.
        var wanted = $"/var/db/macdiag-test-{Guid.NewGuid():N}/x";

        RequireRootOnlyDirectory(wanted, "--artifacts");

        Assert.False(Directory.Exists(Path.GetDirectoryName(wanted)));
    }
}
