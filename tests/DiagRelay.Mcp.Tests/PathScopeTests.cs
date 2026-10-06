using System.Collections;

namespace DiagRelay.Mcp.Tests;

/// <summary>
/// Containment must follow the filesystem's case rules. A case-insensitive check on a case-sensitive
/// filesystem admits a directory that differs from the root only by case -- which is a different
/// directory -- so the boundary is quietly wider than it claims.
/// </summary>
public sealed class PathScopeTests
{
    private static readonly string Root = Path.Combine(Path.GetTempPath(), "Artifacts");
    private static readonly string CaseVariant = Path.Combine(Path.GetTempPath(), "artifacts", "secret.txt");

    [Fact]
    public void A_case_sensitive_comparison_does_not_admit_a_directory_differing_only_by_case()
    {
        // Runs everywhere: pins the logic of the Linux branch without needing Linux.
        Assert.False(PathScope.IsUnder(Path.GetFullPath(CaseVariant), Root, StringComparison.Ordinal));
    }

    [Fact]
    public void A_case_insensitive_comparison_admits_it()
    {
        Assert.True(PathScope.IsUnder(Path.GetFullPath(CaseVariant), Root, StringComparison.OrdinalIgnoreCase));
    }

    [UnixFact]
    public void Unix_compares_paths_case_sensitively_by_default()
    {
        // Including macOS. APFS is case-insensitive by default but can be formatted case-sensitive, and
        // this is a confinement boundary: it fails closed.
        Assert.Equal(StringComparison.Ordinal, PathScope.PathComparison);
        Assert.False(PathScope.IsUnder(Path.GetFullPath(CaseVariant), Root));
    }

    [WindowsFact]
    public void Windows_compares_paths_case_insensitively_by_default()
    {
        Assert.Equal(StringComparison.OrdinalIgnoreCase, PathScope.PathComparison);
        Assert.True(PathScope.IsUnder(Path.GetFullPath(CaseVariant), Root));
    }

    [UnixFact]
    public void Two_roots_differing_only_by_case_both_survive_on_unix()
    {
        // The dedup's mirror bug: collapsing them silently dropped a root the operator configured.
        var upper = Path.Combine(Path.GetTempPath(), "Builds");
        var lower = Path.Combine(Path.GetTempPath(), "builds");

        var roots = RelayFileScope.Roots(new Hashtable { [RelayFileScope.RootsVariable] = $"{upper};{lower}" });

        Assert.Equal([upper, lower], roots);
    }

    [UnixFact]
    public void A_differently_cased_variable_is_not_read_on_unix()
    {
        // Environment variable names are case-sensitive on Unix, and this one sets the confinement root.
        var roots = RelayFileScope.Roots(new Hashtable { ["sysdiag_relay_file_root"] = "/" });

        Assert.DoesNotContain("/", roots);
        Assert.Equal(RelayFileScope.DefaultRoots, roots);
    }

    [WindowsFact]
    public void A_differently_cased_variable_is_read_on_windows()
    {
        var elsewhere = Path.Combine(Path.GetTempPath(), "elsewhere");

        var roots = RelayFileScope.Roots(new Hashtable { ["sysdiag_relay_file_root"] = elsewhere });

        Assert.Equal([elsewhere], roots);
    }
}

/// <summary>
/// The scope tests again, in paths the current OS actually uses. The originals are written in Windows
/// shapes; on Linux a backslash is an ordinary filename character, so they could not tell a working
/// check from a broken one there.
/// </summary>
public sealed class RelayFileScopePortableTests
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"diag-scope-{Guid.NewGuid():N}");

    [UnixFact]
    public void The_default_artifact_root_is_not_the_shared_temp_directory_on_unix()
    {
        // On Linux the temp directory is /tmp, shared and world-writable: another user could create
        // /tmp/sysdiag first and own it, read every dump pulled into it, and plant files inside
        // push_file's default scope for the next deploy to send to a target.
        Assert.False(
            PathScope.IsUnder(RelayFileScope.DefaultArtifactRoot, Path.GetTempPath()),
            $"'{RelayFileScope.DefaultArtifactRoot}' is under the shared temp directory '{Path.GetTempPath()}'.");
    }

    [Fact]
    public void The_roots_variable_is_SYSDIAG_RELAY_FILE_ROOT()
    {
        // Pinned as a literal: the other tests use the constant, so they cannot notice it being renamed.
        var builds = Path.Combine(_root, "builds");

        var roots = RelayFileScope.Roots(new Hashtable { ["SYSDIAG_RELAY_FILE_ROOT"] = builds });

        Assert.Equal([builds], roots);
    }

    [Fact]
    public void The_old_variable_name_is_no_longer_read()
    {
        // A hard rename: an operator who still sets the old name gets the defaults, never the old value.
        var roots = RelayFileScope.Roots(new Hashtable { ["WINDIAG_RELAY_FILE_ROOT"] = Path.GetPathRoot(_root)! });

        Assert.Equal(RelayFileScope.DefaultRoots, roots);
    }

    [Fact]
    public void The_per_user_artifact_folder_is_named_sysdiag()
    {
        Assert.Equal("sysdiag", Path.GetFileName(RelayFileScope.DefaultArtifactRoot));
    }

    [Fact]
    public void The_variable_replaces_the_defaults_rather_than_adding_to_them()
    {
        // Setting the variable is how an operator narrows the boundary; if it only added roots, the two
        // defaults would stay reachable however carefully it was written.
        var builds = Path.Combine(_root, "builds");
        var dumps = Path.Combine(_root, "dumps");

        var roots = RelayFileScope.Roots(new Hashtable { [RelayFileScope.RootsVariable] = $"{builds};{dumps}" });

        Assert.Equal([builds, dumps], roots);
        Assert.DoesNotContain(RelayFileScope.DefaultArtifactRoot, roots);
    }

    [Fact]
    public void A_path_inside_a_root_is_allowed()
    {
        var inside = Path.Combine(_root, "win-x64", "WinDiag.Mcp.exe");

        Assert.Equal(inside, RelayFileScope.Require(inside, "localPath", [_root]));
    }

    [Fact]
    public void A_traversal_out_of_a_root_is_judged_by_where_it_lands()
    {
        var climbing = Path.Combine(_root, "..", "secret.txt");

        Assert.Throws<RelayException>(() => RelayFileScope.Require(climbing, "localPath", [_root]));
    }

    [Fact]
    public void A_sibling_directory_sharing_a_prefix_is_not_inside_the_root()
    {
        var sibling = _root + "X" + Path.DirectorySeparatorChar + "secret.txt";

        Assert.Throws<RelayException>(() => RelayFileScope.Require(sibling, "localPath", [_root]));
    }

    [Fact]
    public void A_path_outside_every_root_is_refused_and_the_roots_are_named()
    {
        var outside = Path.Combine(Path.GetTempPath(), $"elsewhere-{Guid.NewGuid():N}", "id_rsa");

        var ex = Assert.Throws<RelayException>(() => RelayFileScope.Require(outside, "localPath", [_root]));

        Assert.Contains(_root, ex.Message, StringComparison.Ordinal);
        Assert.Contains(RelayFileScope.RootsVariable, ex.Message, StringComparison.Ordinal);
    }
}

/// <summary>
/// The relay's roots judged on real paths. A lexical check alone lets a link planted inside a root carry
/// push_file's read, or pull_file's write, anywhere the link points, while the path in the request still
/// looks confined.
/// </summary>
/// <remarks>
/// Unix only: creating a symbolic link on Windows needs a privilege a test host usually lacks, and the
/// walk itself is shared with the server, whose suite covers junctions on Windows.
/// </remarks>
public sealed class RelayFileScopeLinkTests : IDisposable
{
    private readonly string _base = Directory.CreateDirectory(
        Path.Combine(Path.GetTempPath(), $"diag-links-{Guid.NewGuid():N}")).FullName;

    private string Root => Directory.CreateDirectory(Path.Combine(_base, "root")).FullName;

    private string Outside => Directory.CreateDirectory(Path.Combine(_base, "outside")).FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(_base, recursive: true);
        }
        catch (IOException)
        {
            // Best effort: a leftover temp directory must not fail the test that made it.
        }
    }

    [UnixFact]
    public void A_link_inside_a_root_to_a_file_outside_it_is_refused()
    {
        // What push_file would read: the request names root/keys, the bytes come from outside/id_ed25519.
        var secret = Path.Combine(Outside, "id_ed25519");
        File.WriteAllText(secret, "private key");
        var link = Path.Combine(Root, "keys");
        File.CreateSymbolicLink(link, secret);

        var ex = Assert.Throws<RelayException>(() => RelayFileScope.Require(link, "localPath", [Root]));

        // Named by where it really is: on macOS the temp directory itself sits behind /var -> /private/var.
        Assert.Contains(PathScope.RealPath(secret), ex.Message, StringComparison.Ordinal);
    }

    [UnixFact]
    public void A_linked_directory_inside_a_root_cannot_carry_a_new_file_outside_it()
    {
        // What pull_file would write: the file does not exist yet, but the directory it goes into is a link.
        Directory.CreateSymbolicLink(Path.Combine(Root, "dumps"), Outside);

        Assert.Throws<RelayException>(
            () => RelayFileScope.Require(Path.Combine(Root, "dumps", "authorized_keys"), "localPath", [Root]));
    }

    [UnixFact]
    public void A_link_whose_target_climbs_through_another_link_is_judged_where_the_kernel_lands()
    {
        // root/hop -> outside/deep/dir, and root/trick -> "hop/../f". Collapsed as spelled that is root/f,
        // inside; the kernel goes through hop first and opens outside/deep/f.
        var deep = Directory.CreateDirectory(Path.Combine(Outside, "deep", "dir")).FullName;
        File.WriteAllText(Path.Combine(Outside, "deep", "f"), "secret");
        Directory.CreateSymbolicLink(Path.Combine(Root, "hop"), deep);
        File.CreateSymbolicLink(Path.Combine(Root, "trick"), Path.Combine("hop", "..", "f"));

        Assert.Throws<RelayException>(
            () => RelayFileScope.Require(Path.Combine(Root, "trick"), "localPath", [Root]));
    }

    [UnixFact]
    public void A_root_reached_through_a_link_still_admits_what_is_inside_it()
    {
        // Both sides are resolved, so an operator whose builds folder is itself a link is not refused.
        var real = Directory.CreateDirectory(Path.Combine(Outside, "builds")).FullName;
        var linkedRoot = Path.Combine(_base, "builds");
        Directory.CreateSymbolicLink(linkedRoot, real);
        var inside = Path.Combine(linkedRoot, "win-x64", "WinDiag.Mcp.exe");

        Assert.Equal(inside, RelayFileScope.Require(inside, "localPath", [linkedRoot]));
    }

    [UnixFact]
    public void A_link_that_stays_inside_the_root_is_allowed()
    {
        var build = Path.Combine(Root, "win-x64", "WinDiag.Mcp.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(build)!);
        File.WriteAllText(build, "build");
        var latest = Path.Combine(Root, "latest");
        File.CreateSymbolicLink(latest, build);

        Assert.Equal(latest, RelayFileScope.Require(latest, "localPath", [Root]));
    }

    [UnixFact]
    public void A_link_loop_inside_a_root_is_refused_rather_than_followed_forever()
    {
        File.CreateSymbolicLink(Path.Combine(Root, "a"), Path.Combine(Root, "b"));
        File.CreateSymbolicLink(Path.Combine(Root, "b"), Path.Combine(Root, "a"));

        Assert.Throws<RelayException>(
            () => RelayFileScope.Require(Path.Combine(Root, "a", "x"), "localPath", [Root]));
    }
}
