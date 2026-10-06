using Diag.Mcp.Server.Files;

namespace Diag.Mcp.Server.Tests;

/// <summary>
/// A Windows link whose target names a volume or device rather than a drive letter is not judged as a
/// child of the link's own folder.
/// </summary>
/// <remarks>
/// <para>.NET hands back a junction's or absolute symlink's target with the NT <c>\??\</c> prefix
/// removed. For <c>\??\C:\x</c> that leaves <c>C:\x</c>, which is rooted. For a mounted folder,
/// <c>\??\Volume{guid}\</c>, it leaves <c>Volume{guid}\</c>, and for <c>\??\GLOBALROOT\Device\...</c>
/// <c>GLOBALROOT\Device\...</c> -- both of which look relative. The walk then spliced them under the
/// link's folder, so a mounted folder inside the artifact directory read as owned while a get_file or
/// put_file through it reached another volume, the root of this one, or a shadow copy.</para>
/// <para>The walk's own logic is platform-neutral, so these run everywhere through a fake link table; the
/// separator is this OS's, which is all the Windows rule needs to be exercised on Linux and macOS.</para>
/// </remarks>
public sealed class NtNamespaceLinkTests
{
    private static readonly string Owned = Path.Combine(Path.GetTempPath(), "nt-namespace-fake-owned");
    private static readonly string Link = Path.Combine(Owned, "mnt");

    private static (string Path, bool CrossesMagicLink) WalkThrough(string target, bool windowsRule) =>
        FileScope.Walk(
            Path.Combine(Link, "Windows", "win.ini"),
            path => path == Link ? target : null,
            relativeTargetsBySpelling: windowsRule,
            isMagicLink: null);

    public static TheoryData<string> NtTargets => new()
    {
        "Volume{11111111-1111-1111-1111-111111111111}" + Path.DirectorySeparatorChar,
        "volume{11111111-1111-1111-1111-111111111111}",
        Path.Combine("GLOBALROOT", "Device", "HarddiskVolumeShadowCopy1"),
        Path.Combine("HarddiskVolume3", "Windows"),
        Path.Combine("Global", "C:", "Windows"),
        Path.Combine("PhysicalDrive0"),
    };

    [Theory]
    [MemberData(nameof(NtTargets))]
    public void A_windows_link_to_a_volume_or_device_name_stops_the_walk_as_unjudgeable(string target)
    {
        var (real, crossesMagicLink) = WalkThrough(target, windowsRule: true);

        // Unjudgeable, so Classify calls it Arbitrary: reaching it needs the arbitrary grant, as a path
        // through a procfs magic link already does. Spliced under the link, it would have been Owned.
        Assert.True(crossesMagicLink);
        Assert.Equal(Path.Combine(Link, "Windows", "win.ini"), real);
    }

    [Fact]
    public void An_ordinary_relative_windows_link_target_is_still_followed_under_the_links_folder()
    {
        var (real, crossesMagicLink) = WalkThrough("Volumes" + Path.DirectorySeparatorChar + "data", windowsRule: true);

        Assert.False(crossesMagicLink);
        Assert.Equal(Path.Combine(Owned, "Volumes", "data", "Windows", "win.ini"), real);
    }

    [Fact]
    public void The_posix_rule_is_unchanged_and_follows_a_directory_that_happens_to_be_named_like_a_volume()
    {
        // On Linux and macOS a relative target is only ever a relative path: there is no NT namespace for
        // it to name, so the fix must not reach this branch.
        var target = "Volume{11111111-1111-1111-1111-111111111111}";

        var (real, crossesMagicLink) = WalkThrough(target, windowsRule: false);

        Assert.False(crossesMagicLink);
        Assert.Equal(Path.Combine(Owned, target, "Windows", "win.ini"), real);
    }
}
