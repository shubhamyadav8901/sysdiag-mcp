using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using WinDiag.Mcp.Hosting;

namespace WinDiag.Mcp.Tests;

/// <summary>Builds the links and trees these tests plant, the way a local user would.</summary>
internal static class PlantedTree
{
    /// <summary>A directory link at <paramref name="link"/>: a junction on Windows, which needs no privilege, a symbolic link elsewhere.</summary>
    public static void LinkDirectory(string link, string target)
    {
        if (OperatingSystem.IsWindows())
        {
            Cmd($"mklink /J \"{link}\" \"{target}\"");
        }
        else
        {
            Directory.CreateSymbolicLink(link, target);
        }
    }

    /// <summary>A second name for an existing file. Windows only: .NET has no API for it.</summary>
    public static void HardLink(string link, string target) => Cmd($"mklink /H \"{link}\" \"{target}\"");

    /// <summary>
    /// <paramref name="path"/> with every link in it resolved, so a test's own temporary directory does not
    /// read as reached through a link: on macOS it is under /var, which is one.
    /// </summary>
    public static string RealPath(string path)
    {
        var full = Path.GetFullPath(path);
        var current = Path.GetPathRoot(full)!;
        foreach (var part in full[current.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            if (new DirectoryInfo(current).ResolveLinkTarget(returnFinalTarget: true) is { } target)
            {
                current = target.FullName;
            }
        }

        return current;
    }

    /// <summary>A new directory directly under the system drive's root, which hands it "Authenticated Users: Modify" as C:\WinDiag gets.</summary>
    public static string UnderSystemDriveRoot() =>
        Directory.CreateDirectory(Path.Combine(Path.GetPathRoot(Environment.SystemDirectory)!, $"windiag-test-{Guid.NewGuid():N}")).FullName;

    public static void GrantEveryoneFullControl(FileInfo file)
    {
        var acl = file.GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        file.SetAccessControl(acl);
    }

    /// <summary>What a user left in a directory while it was writable: files granting everyone write, one hidden, one a level down.</summary>
    public static string[] Plant(string root)
    {
        var nested = Directory.CreateDirectory(Path.Combine(root, "nested")).FullName;
        var files = new[] { Path.Combine(root, "handle64.exe"), Path.Combine(root, "hidden.dll"), Path.Combine(nested, "self-update.cmd") };
        foreach (var file in files)
        {
            File.WriteAllText(file, "planted");
            GrantEveryoneFullControl(new FileInfo(file));
        }

        File.SetAttributes(files[1], FileAttributes.Hidden);
        return files;
    }

    /// <summary>Deletes what a test made, links included, without following them.</summary>
    public static void Remove(string path)
    {
        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
            // Never made: the test failed before it got that far.
        }
    }

    private static void Cmd(string command)
    {
        using var process = Process.Start(new ProcessStartInfo("cmd.exe", $"/c {command}")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        })!;
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, $"{command}: {output}");
    }
}

/// <summary>
/// A server or artifact directory that is a link, or is reached through one, is refused: whoever made the
/// link can point it elsewhere once the directory has been judged safe.
/// </summary>
/// <remarks>Judged by attributes alone, so this runs on any OS: with a junction on Windows, a symbolic link elsewhere.</remarks>
public sealed class DirectoryLinkRefusalTests : IDisposable
{
    private readonly string _root = PlantedTree.RealPath(Directory.CreateTempSubdirectory("windiag-links-").FullName);

    public void Dispose() => PlantedTree.Remove(_root);

    [Fact]
    public void Refuses_a_directory_that_is_itself_a_link_a_user_could_point_somewhere_else()
    {
        // C:\WinDiagArtifacts made by a user as a junction into their own folder: restricting it restricts
        // the target, and the junction stays theirs to retarget once the service has been told it is safe.
        var target = Directory.CreateDirectory(Path.Combine(_root, "theirs")).FullName;
        var link = Path.Combine(_root, "WinDiagArtifacts");
        PlantedTree.LinkDirectory(link, target);

        var ex = Assert.Throws<ConfigurationException>(() => ProtectedAcl.RefuseLinks(link));

        Assert.Contains(link, ex.Message, StringComparison.Ordinal);
        Assert.Contains("is a link", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Refuses_a_directory_reached_through_a_link_above_it_even_when_it_does_not_exist_yet()
    {
        // The same thing a level up: --artifacts C:\Lab\artifacts with C:\Lab a user's junction. The artifact
        // directory is made on the first start, so a missing one must be judged by what is above it.
        var target = Directory.CreateDirectory(Path.Combine(_root, "theirs")).FullName;
        var link = Path.Combine(_root, "Lab");
        PlantedTree.LinkDirectory(link, target);
        Directory.CreateDirectory(Path.Combine(target, "existing"));

        foreach (var below in new[] { Path.Combine(link, "existing"), Path.Combine(link, "not-made-yet", "artifacts") })
        {
            var ex = Assert.Throws<ConfigurationException>(() => ProtectedAcl.RefuseLinks(below));
            Assert.Contains($"{link} is a link", ex.Message, StringComparison.Ordinal);
            Assert.Contains($"{below} is reached through it", ex.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Accepts_a_directory_reached_only_through_real_directories_whether_or_not_it_exists_yet()
    {
        var real = Directory.CreateDirectory(Path.Combine(_root, "WinDiag")).FullName;

        ProtectedAcl.RefuseLinks(real);
        ProtectedAcl.RefuseLinks(Path.Combine(real, "not-made-yet", "artifacts"));
    }
}

/// <summary>
/// What <see cref="ProtectedAcl.ProtectDirectory"/> and <see cref="ProtectedAcl.DirectoryExposures"/> do to and
/// see in a real directory under the system drive's root, which inherits what C:\WinDiag does.
/// </summary>
/// <remarks>
/// Elevated Windows only, as the installer and the service are: CI's Windows runner. Each test first shows
/// the state it starts from, so a pass cannot mean the machine was locked down to begin with.
/// </remarks>
public sealed class ProtectDirectoryOnDiskTests : IDisposable
{
    private static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);
    private static readonly SecurityIdentifier NetworkService = new(WellKnownSidType.NetworkServiceSid, null);

    private readonly List<string> _made = [];

    // Newest first, so a junction goes before the directory it points to.
    public void Dispose() => Enumerable.Reverse(_made).ToList().ForEach(PlantedTree.Remove);

    private string NewDirectory()
    {
        var path = PlantedTree.UnderSystemDriveRoot();
        _made.Add(path);
        return path;
    }

    private static FileSystemSecurity Acl(string path) =>
        Directory.Exists(path)
            ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner)
            : new FileInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);

    private static IEnumerable<FileSystemAccessRule> Rules(string path, bool inherited) =>
        Acl(path).GetAccessRules(includeExplicit: !inherited, includeInherited: inherited, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>();

    [ElevatedFact]
    public void Takes_over_what_a_user_left_in_the_directory_so_nothing_in_it_stays_theirs_to_rewrite()
    {
        // The upgrade path: a target an older build left writable, holding a self-update.cmd or a signed
        // handle64.exe a user made. Restricting only the directory left each file its owner, who could grant
        // themselves write again and rewrite it while SYSTEM waited to run it.
        var path = NewDirectory();
        var planted = PlantedTree.Plant(path);
        Assert.NotEmpty(ProtectedAcl.DirectoryExposures(path, NetworkService));

        ProtectedAcl.ProtectDirectory(path, NetworkService, ownedByAdministrators: true);

        Assert.Empty(ProtectedAcl.DirectoryExposures(path, NetworkService));
        foreach (var file in planted.Append(Path.Combine(path, "nested")))
        {
            Assert.Equal(ProtectedAcl.Administrators, Acl(file).GetOwner(typeof(SecurityIdentifier)));
            Assert.DoesNotContain(Rules(file, inherited: false).Concat(Rules(file, inherited: true)), r => r.IdentityReference.Equals(Everyone));

            // Inheritance left on, so the service account's ACE on the directory still reaches what it runs
            // and writes; and explicit rules present, never the empty ACL .NET writes as Everyone: Full Control.
            Assert.Contains(Rules(file, inherited: true), r => r.IdentityReference.Equals(NetworkService));
            Assert.Contains(Rules(file, inherited: false), r => r.IdentityReference.Equals(ProtectedAcl.LocalSystem));
        }
    }

    [ElevatedFact]
    public void Reports_a_file_a_user_can_write_inside_a_directory_that_is_itself_protected()
    {
        // The service's start-time check: a directory whose own ACL is right but which holds a file somebody
        // else can rewrite is not protected, and must be repaired or refused rather than passed.
        var path = NewDirectory();
        ProtectedAcl.ProtectDirectory(path, serviceAccount: null, ownedByAdministrators: true);
        Assert.Empty(ProtectedAcl.DirectoryExposures(path, serviceAccount: null));

        var file = Path.Combine(path, "self-update.cmd");
        File.WriteAllText(file, "@echo off");
        PlantedTree.GrantEveryoneFullControl(new FileInfo(file));

        var exposure = Assert.Single(ProtectedAcl.DirectoryExposures(path, serviceAccount: null));
        Assert.Contains(file, exposure, StringComparison.Ordinal);
    }

    [ElevatedFact]
    public void Refuses_a_directory_that_is_a_junction_and_leaves_where_it_points_as_it_was()
    {
        var target = NewDirectory();
        var link = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory)!, $"windiag-test-{Guid.NewGuid():N}");
        _made.Add(link);
        PlantedTree.LinkDirectory(link, target);
        var before = Acl(target).GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner);

        Assert.Throws<ConfigurationException>(() => ProtectedAcl.ProtectDirectory(link, serviceAccount: null, ownedByAdministrators: true));
        Assert.Throws<ConfigurationException>(() => ProtectedAcl.DirectoryExposures(link, serviceAccount: null));

        Assert.Equal(before, Acl(target).GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner));
    }

    [ElevatedFact]
    public void Refuses_a_directory_reached_through_a_junction_and_creates_nothing_beyond_it()
    {
        var target = NewDirectory();
        var link = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory)!, $"windiag-test-{Guid.NewGuid():N}");
        _made.Add(link);
        PlantedTree.LinkDirectory(link, target);

        Assert.Throws<ConfigurationException>(
            () => ProtectedAcl.ProtectDirectory(Path.Combine(link, "artifacts"), serviceAccount: null, ownedByAdministrators: true));

        Assert.False(Directory.Exists(Path.Combine(target, "artifacts")));
    }

    [ElevatedFact]
    public void Refuses_a_directory_holding_a_junction_before_changing_anything_in_it()
    {
        // Taking the contents over through a junction would rewrite the ACLs of wherever it points.
        var path = NewDirectory();
        var elsewhere = NewDirectory();
        PlantedTree.LinkDirectory(Path.Combine(path, "System32"), elsewhere);
        var exposed = ProtectedAcl.DirectoryExposures(path, serviceAccount: null);
        Assert.Contains(exposed, e => e.Contains("is a link", StringComparison.Ordinal));
        var before = Acl(elsewhere).GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner);

        var ex = Assert.Throws<ConfigurationException>(() => ProtectedAcl.ProtectDirectory(path, serviceAccount: null, ownedByAdministrators: true));

        Assert.Contains("is a link", ex.Message, StringComparison.Ordinal);
        Assert.NotEmpty(ProtectedAcl.Exposures(Acl(path), ProtectedAcl.DirectoryWriteRights, ProtectedAcl.Trusted(null), "write to"));
        Assert.Equal(before, Acl(elsewhere).GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner));
    }

    [ElevatedFact]
    public void Refuses_a_hard_link_whose_other_name_is_outside_the_directory_and_leaves_that_file_as_it_was()
    {
        // A user can give any file they can read a second name in a directory they can write. Taking it over
        // would change the original -- a System32 binary, say -- and hand it to the service's account.
        var path = NewDirectory();
        var elsewhere = NewDirectory();
        var original = Path.Combine(elsewhere, "original.dll");
        File.WriteAllText(original, "not windiag's");
        PlantedTree.HardLink(Path.Combine(path, "dbghelp.dll"), original);
        var before = Acl(original).GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner);

        // The service's start-time check names it too, so the check and the repair agree on what is wrong.
        Assert.Contains(ProtectedAcl.DirectoryExposures(path, NetworkService), e => e.Contains("hard link", StringComparison.Ordinal));

        var ex = Assert.Throws<ConfigurationException>(() => ProtectedAcl.ProtectDirectory(path, NetworkService, ownedByAdministrators: true));

        Assert.Contains("hard link", ex.Message, StringComparison.Ordinal);
        Assert.Equal(before, Acl(original).GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner));
    }

    [ElevatedFact]
    public void Creates_a_missing_directory_with_the_protected_acl_already_on_it()
    {
        // Created and then restricted, it would inherit "Authenticated Users: Modify" in between, and a
        // handle a user opened then keeps that access whatever the ACL later says.
        var parent = NewDirectory();
        var path = Path.Combine(parent, "WinDiagArtifacts", "dumps");

        ProtectedAcl.ProtectDirectory(path, serviceAccount: null, ownedByAdministrators: true);

        foreach (var made in new[] { Path.GetDirectoryName(path)!, path })
        {
            Assert.True(Acl(made).AreAccessRulesProtected);
            Assert.Empty(Rules(made, inherited: true));
            Assert.Empty(ProtectedAcl.DirectoryExposures(made, serviceAccount: null));
        }
    }
}

/// <summary>Which reparse points count as links: anything that could lead elsewhere, and not the data tags Windows Server puts on ordinary files.</summary>
public sealed class ReparsePointClassificationTests
{
    private const uint ReparsePoint = (uint)FileAttributes.ReparsePoint;
    private const uint Directory = (uint)FileAttributes.Directory;

    [Theory]
    [InlineData(0x80000013u)] // deduplication
    [InlineData(0x80000017u)] // compact /exe
    public void A_deduplicated_or_compressed_file_is_not_a_link_so_a_dump_or_the_server_binary_is_not_refused(uint tag)
    {
        // A data volume with deduplication, or compact /exe on C:\WinDiag, puts these tags on files that
        // are entirely ordinary. Counted as links, the next start after update_self refused to run.
        Assert.False(FileObjects.IsLink(ReparsePoint, tag));
    }

    [Theory]
    [InlineData(0xA0000003u)] // a junction or mounted volume
    [InlineData(0xA000000Cu)] // a symbolic link
    [InlineData(0x9000001Au)] // a cloud placeholder, whose data a user-run sync engine supplies
    [InlineData(0x12345678u)] // anything not known to be harmless
    public void A_file_with_any_other_tag_is_a_link(uint tag) => Assert.True(FileObjects.IsLink(ReparsePoint, tag));

    [Fact]
    public void A_directory_that_is_a_reparse_point_of_any_kind_is_a_link()
    {
        Assert.True(FileObjects.IsLink(ReparsePoint | Directory, 0x80000013u));
        Assert.False(FileObjects.IsLink(Directory, 0));
        Assert.False(FileObjects.IsLink(0, 0));
    }
}
