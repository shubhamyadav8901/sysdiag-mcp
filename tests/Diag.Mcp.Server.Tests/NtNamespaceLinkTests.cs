using Diag.Mcp.Server.Files;

namespace Diag.Mcp.Server.Tests;

/// <summary>
/// A Windows link whose target .NET hands back without a root is never judged as a child of the link's
/// own folder, whatever the target says.
/// </summary>
/// <remarks>
/// <para>.NET 9 hands back a junction's or absolute symlink's target with its first four characters cut
/// off, on the assumption that they are the NT <c>\??\</c> prefix; nothing checks that they are. For
/// <c>\??\C:\x</c> that leaves <c>C:\x</c>, which is rooted. For a mounted folder, <c>\??\Volume{guid}\</c>,
/// it leaves <c>Volume{guid}\</c>; for <c>\??\GLOBALROOT\Device\...</c>, <c>GLOBALROOT\Device\...</c>; and
/// for a junction any user can point at <c>\Device\HarddiskVolume3\</c>, <c>ice\HarddiskVolume3\</c>. All
/// of them look relative. The walk spliced them under the link's folder, so a link inside the artifact
/// directory read as owned while a get_file or put_file through it reached another volume, the root of
/// this one, or a shadow copy.</para>
/// <para>A first fix recognised the volume and device names; the cut-off <c>\Device\</c> spelling was not
/// one of them. Only the reparse tag says whether a target was relative, and .NET does not expose it, so
/// no spelling can be trusted: every unrooted Windows target stops the walk.</para>
/// <para>The walk's own logic is platform-neutral, so these run everywhere through a fake link table; the
/// separator is this OS's, which is all the Windows rule needs to be exercised on Linux and macOS.</para>
/// </remarks>
public sealed class NtNamespaceLinkTests
{
    private static readonly string Owned = Path.Combine(Path.GetTempPath(), "nt-namespace-fake-owned");
    private static readonly string Link = Path.Combine(Owned, "mnt");
    private static readonly char Sep = Path.DirectorySeparatorChar;

    private static (string Path, bool CrossesMagicLink) WalkThrough(
        string target, bool windowsRule, List<string>? lookedUp = null) =>
        FileScope.Walk(
            Path.Combine(Link, "Windows", "win.ini"),
            path =>
            {
                lookedUp?.Add(path);
                return path == Link ? target : null;
            },
            windowsTargets: windowsRule,
            isMagicLink: null);

    public static TheoryData<string> UnrootedTargets => new()
    {
        // What .NET returns for \??\Volume{guid}\, a mounted folder.
        "Volume{11111111-1111-1111-1111-111111111111}" + Sep,
        // \??\GLOBALROOT\Device\HarddiskVolumeShadowCopy1: a shadow copy.
        Path.Combine("GLOBALROOT", "Device", "HarddiskVolumeShadowCopy1"),
        // \Device\HarddiskVolume3\ and \Device\HarddiskVolumeShadowCopy1\, with "\Dev" cut off: a junction
        // any user may create, and no name list caught it.
        "ice" + Sep + "HarddiskVolume3" + Sep,
        "ice" + Sep + "HarddiskVolumeShadowCopy1" + Sep,
        // \??\Global\C:\Windows: a drive spelled through the global namespace.
        Path.Combine("Global", "C:", "Windows"),
        // A genuinely relative symlink. Indistinguishable from the above by its text, so it is stopped too.
        Path.Combine("Volumes", "data"),
        Path.Combine("..", "elsewhere"),
    };

    [Theory]
    [MemberData(nameof(UnrootedTargets))]
    public void A_windows_link_whose_target_has_no_root_stops_the_walk_as_unjudgeable(string target)
    {
        var (real, crossesMagicLink) = WalkThrough(target, windowsRule: true);

        // Unjudgeable, so Classify calls it Arbitrary: reaching it needs the arbitrary grant, as a path
        // through a procfs magic link already does. Spliced under the link, it would have been Owned.
        Assert.True(crossesMagicLink);
        Assert.Equal(Path.Combine(Link, "Windows", "win.ini"), real);
    }

    [Fact]
    public void A_windows_link_to_a_share_stops_the_walk_before_anything_on_the_share_is_looked_up()
    {
        // An absolute symlink to \??\UNC\host\share comes back as \\host\share. Walking on from there is
        // the SMB connection the network-path rule exists to prevent, made from inside an owned directory.
        var share = Sep == '/' ? "//attacker/share" : @"\\attacker\share";
        var lookedUp = new List<string>();

        var (_, crossesMagicLink) = WalkThrough(share, windowsRule: true, lookedUp);

        Assert.True(crossesMagicLink);
        Assert.Contains(Link, lookedUp);
        Assert.DoesNotContain(lookedUp, path => path.Contains("attacker", StringComparison.Ordinal));
    }

    [Fact]
    public void A_windows_link_to_a_drive_path_is_still_followed_from_that_drives_root()
    {
        // \??\C:\data comes back rooted, which is the one spelling .NET reports faithfully.
        var elsewhere = Path.Combine(Path.GetTempPath(), "nt-namespace-fake-elsewhere");

        var (real, crossesMagicLink) = WalkThrough(elsewhere, windowsRule: true);

        Assert.False(crossesMagicLink);
        Assert.Equal(Path.Combine(elsewhere, "Windows", "win.ini"), real);
    }

    [Fact]
    public void An_owned_directory_behind_a_mounted_folder_is_refused_with_advice_the_operator_can_follow()
    {
        // A data disk mounted only at C:\Data has no drive-letter spelling to "configure by", and its
        // \\?\Volume{guid}\ spelling is refused as a device. The message has to say what does work.
        var artifacts = Path.Combine(Owned, "art");
        var server = Path.Combine(Owned, "srv");
        var options = new FileTransferOptions(artifacts, false, false, "W=1", "R=1");

        var ex = Assert.Throws<FileTransferException>(() => FileScope.Classify(
            Path.Combine(server, "x"), options, server, replacesFinalLink: false, looseServerMatch: false,
            isNetworkOrDevice: _ => false,
            walk: path => (path, path.StartsWith(artifacts, StringComparison.Ordinal))));

        Assert.Contains(artifacts, ex.Message, StringComparison.Ordinal);
        Assert.Contains("mounted", ex.Message, StringComparison.Ordinal);
        Assert.Contains("drive letter", ex.Message, StringComparison.Ordinal);
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
