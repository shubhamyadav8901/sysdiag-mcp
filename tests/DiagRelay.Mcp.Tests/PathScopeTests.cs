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
        Assert.Contains(RelayFileScope.DefaultBuildRoot, roots);
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

        Assert.Equal([RelayFileScope.DefaultBuildRoot, RelayFileScope.DefaultArtifactRoot], roots);
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
        Assert.DoesNotContain(RelayFileScope.DefaultBuildRoot, roots);
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
