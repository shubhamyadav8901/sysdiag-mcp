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
    /// Hands <paramref name="path"/> itself -- a link, not what it leads to -- to Administrators, as an item an
    /// administrator put there is owned when Windows gives new objects to that group rather than to whoever made them.
    /// </summary>
    /// <remarks>
    /// Made by this elevated test, an item is owned by the account running it on a machine that gives new
    /// objects to their creator, which counts as somebody other than SYSTEM and Administrators.
    /// </remarks>
    public static void OwnByAdministrators(string path) => Cmd($"icacls \"{path}\" /setowner *S-1-5-32-544 /L /Q");

    /// <summary>Hands <paramref name="path"/> itself to <paramref name="owner"/>, which needs the restore privilege icacls enables.</summary>
    public static void SetOwner(string path, SecurityIdentifier owner) => Cmd($"icacls \"{path}\" /setowner *{owner.Value} /L /Q");

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

    internal static void Cmd(string command)
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

            // What an item created there afresh gets: no explicit ACE, inheritance left on so the service
            // account's ACE on the directory still reaches what it runs and writes -- and never the empty ACL
            // .NET writes as Everyone: Full Control.
            Assert.False(Acl(file).AreAccessRulesProtected);
            Assert.Empty(Rules(file, inherited: false));
            foreach (var account in new[] { ProtectedAcl.LocalSystem, ProtectedAcl.Administrators, NetworkService })
            {
                Assert.Contains(Rules(file, inherited: true), r => r.IdentityReference.Equals(account));
            }
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
        PlantedTree.OwnByAdministrators(file);
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
        // Below a directory only administrators can change: one any user could rename is refused, see below.
        var parent = NewDirectory();
        ProtectedAcl.ProtectDirectory(parent, serviceAccount: null, ownedByAdministrators: true);
        var path = Path.Combine(parent, "WinDiagArtifacts", "dumps");

        ProtectedAcl.ProtectDirectory(path, serviceAccount: null, ownedByAdministrators: true);

        foreach (var made in new[] { Path.GetDirectoryName(path)!, path })
        {
            Assert.True(Acl(made).AreAccessRulesProtected);
            Assert.Empty(Rules(made, inherited: true));
            Assert.Empty(ProtectedAcl.DirectoryExposures(made, serviceAccount: null));
        }
    }

    [ElevatedFact]
    public void Refuses_a_directory_below_one_any_user_can_rename_and_creates_nothing_there()
    {
        // --artifacts C:\Lab\artifacts, with C:\Lab made by anyone under C:\ -- or made by a user in the moment
        // between finding it missing and creating it. Any user can rename C:\Lab and put their own in its
        // place, and update_self would then write the script SYSTEM runs into a directory of theirs.
        var parent = NewDirectory();
        var path = Path.Combine(parent, "artifacts");
        var before = Acl(parent).GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner);

        var ex = Assert.Throws<ConfigurationException>(() => ProtectedAcl.ProtectDirectory(path, serviceAccount: null, ownedByAdministrators: true));

        Assert.Contains($"{parent} can be renamed", ex.Message, StringComparison.Ordinal);
        Assert.False(Directory.Exists(path));
        Assert.Equal(before, Acl(parent).GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner));

        // The service's start-time check names it too, for a directory that is already there.
        Directory.CreateDirectory(path);
        Assert.Contains(ProtectedAcl.DirectoryExposures(path, serviceAccount: null), e => e.StartsWith($"{parent}, on the way to it:", StringComparison.Ordinal));
    }

    [ElevatedFact]
    public void An_individual_administrator_is_trusted_above_windiags_directories_and_an_ordinary_user_is_not()
    {
        using var admin = new TemporaryLocalUser(administrator: true);
        using var user = new TemporaryLocalUser(administrator: false);

        Assert.Contains(admin.Sid, ProtectedAcl.TrustedAbove(serviceAccount: null));
        Assert.DoesNotContain(user.Sid, ProtectedAcl.TrustedAbove(serviceAccount: null));

        // Not in the directories themselves, which windiag restricts: there a user's own SID would also admit
        // that user's unelevated programs.
        Assert.DoesNotContain(admin.Sid, ProtectedAcl.Trusted(serviceAccount: null));
    }

    [ElevatedFact]
    public void Accepts_a_directory_below_one_only_administrators_can_change_though_an_individual_administrator_owns_it()
    {
        // D:\Ops, locked to administrators by hand but made by the built-in Administrator on Windows Server,
        // whose objects are owned by that account and not by the group. Judged by the group alone it read as
        // that account's to rename, and the service refused every start after update_self, which has no way back.
        using var admin = new TemporaryLocalUser(administrator: true);
        var parent = NewDirectory();
        ProtectedAcl.ProtectDirectory(parent, serviceAccount: null, ownedByAdministrators: true);
        PlantedTree.SetOwner(parent, admin.Sid);
        var path = Path.Combine(parent, "WinDiagArtifacts");

        ProtectedAcl.ProtectDirectory(path, serviceAccount: null, ownedByAdministrators: true);

        Assert.True(Directory.Exists(path));
        Assert.Empty(ProtectedAcl.DirectoryExposures(path, serviceAccount: null));
        Assert.Equal(admin.Sid, Acl(parent).GetOwner(typeof(SecurityIdentifier)));
    }

    [ElevatedFact]
    public void Refuses_a_directory_below_one_an_ordinary_user_owns_and_says_how_to_hand_it_to_administrators()
    {
        // The other side of the line above: an owner outside the Administrators group can grant itself any
        // right, so restricting the ACL alone is not enough, and the refusal must say the owner is the cause.
        using var user = new TemporaryLocalUser(administrator: false);
        var parent = NewDirectory();
        ProtectedAcl.ProtectDirectory(parent, serviceAccount: null, ownedByAdministrators: true);
        PlantedTree.SetOwner(parent, user.Sid);
        var path = Path.Combine(parent, "WinDiagArtifacts");

        var ex = Assert.Throws<ConfigurationException>(() => ProtectedAcl.ProtectDirectory(path, serviceAccount: null, ownedByAdministrators: true));

        Assert.Contains($"{user.Name} owns it", ex.Message, StringComparison.Ordinal);
        Assert.Contains($"icacls \"{parent}\" /setowner *S-1-5-32-544", ex.Message, StringComparison.Ordinal);
        Assert.False(Directory.Exists(path));

        Directory.CreateDirectory(path);
        Assert.Contains(ProtectedAcl.DirectoryExposures(path, serviceAccount: null), e => e.StartsWith($"{parent}, on the way to it:", StringComparison.Ordinal));
    }

    [ElevatedFact]
    public void Neither_a_link_nor_a_hard_link_only_administrators_can_change_counts_against_a_protected_directory()
    {
        // A server directory beside Git for Windows' hard links, or holding a junction an administrator made,
        // started under every earlier build. Nobody but an administrator can change either, so the start-time
        // check must not turn it into a refusal after update_self.
        var path = NewDirectory();
        ProtectedAcl.ProtectDirectory(path, serviceAccount: null, ownedByAdministrators: true);
        var elsewhere = NewDirectory();
        ProtectedAcl.ProtectDirectory(elsewhere, serviceAccount: null, ownedByAdministrators: true);

        var original = Path.Combine(elsewhere, "original.dll");
        File.WriteAllText(original, "an administrator's");
        PlantedTree.OwnByAdministrators(original);
        PlantedTree.HardLink(Path.Combine(path, "git-core.dll"), original);
        var junction = Path.Combine(path, "tools");
        PlantedTree.LinkDirectory(junction, elsewhere);
        PlantedTree.OwnByAdministrators(junction);

        Assert.Empty(ProtectedAcl.DirectoryExposures(path, serviceAccount: null));

        // The same links where anyone may change them are what a user would plant, and are reported.
        PlantedTree.GrantEveryoneFullControl(new FileInfo(original));
        Assert.Contains(ProtectedAcl.DirectoryExposures(path, serviceAccount: null), e => e.Contains("git-core.dll is a hard link, and", StringComparison.Ordinal));
    }

    [ElevatedFact]
    public void Takes_over_an_item_whose_path_is_longer_than_max_path()
    {
        // A raw CreateFileW without the \\?\ prefix fails such a path as not found, which was taken for "gone
        // since the listing": the item was never judged, never refused and never taken over.
        var path = NewDirectory();
        var deep = Path.Combine(path, new string('a', 100), new string('b', 100), new string('c', 100));
        Directory.CreateDirectory(deep);
        var file = Path.Combine(deep, "handle64.exe");
        File.WriteAllText(file, "planted");
        Assert.True(file.Length > 260);
        PlantedTree.GrantEveryoneFullControl(new FileInfo(Long(file)));

        ProtectedAcl.ProtectDirectory(path, serviceAccount: null, ownedByAdministrators: true);

        var acl = new FileInfo(Long(file)).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        Assert.Equal(ProtectedAcl.Administrators, acl.GetOwner(typeof(SecurityIdentifier)));
        Assert.DoesNotContain(
            acl.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(),
            r => r.IdentityReference.Equals(Everyone));
        Assert.Empty(ProtectedAcl.DirectoryExposures(path, serviceAccount: null));
    }

    [ElevatedFact]
    public void Reports_a_directory_it_may_not_list_as_unknown_and_takes_it_over_rather_than_throwing()
    {
        // A user's directory whose DACL keeps the caller from listing it threw a bare access-denied out of the
        // start-time check, and the operator never got the repair or its instructions.
        var path = NewDirectory();
        var nested = Directory.CreateDirectory(Path.Combine(path, "nested")).FullName;
        var file = Path.Combine(nested, "self-update.cmd");
        File.WriteAllText(file, "planted");
        var deny = new FileSystemAccessRule(ProtectedAcl.Administrators, FileSystemRights.ListDirectory, AccessControlType.Deny);
        var nestedAcl = new DirectoryInfo(nested).GetAccessControl();
        nestedAcl.AddAccessRule(deny);
        new DirectoryInfo(nested).SetAccessControl(nestedAcl);
        try
        {
            Assert.Throws<UnauthorizedAccessException>(() => Directory.GetFileSystemEntries(nested));

            Assert.Contains(ProtectedAcl.DirectoryExposures(path, serviceAccount: null), e => e.StartsWith($"{nested}: what it holds cannot be listed", StringComparison.Ordinal));

            ProtectedAcl.ProtectDirectory(path, serviceAccount: null, ownedByAdministrators: true);

            Assert.Empty(ProtectedAcl.DirectoryExposures(path, serviceAccount: null));
            Assert.Equal(ProtectedAcl.Administrators, Acl(file).GetOwner(typeof(SecurityIdentifier)));
        }
        finally
        {
            // So the test's own clean-up can list it, whatever happened above.
            var reset = new DirectoryInfo(nested).GetAccessControl();
            reset.RemoveAccessRuleAll(deny);
            new DirectoryInfo(nested).SetAccessControl(reset);
        }
    }

    [ElevatedFact]
    public void A_server_copied_to_a_drive_root_reads_as_exposed_without_walking_the_drive()
    {
        // C:\WinDiag.Mcp.exe registered as a service: the root has no directory above it to judge, and must
        // still read as what it is -- a directory every user can add to -- so the start is refused.
        var root = Path.GetPathRoot(Environment.SystemDirectory)!;
        var started = Stopwatch.StartNew();

        Assert.NotEmpty(ProtectedAcl.DirectoryExposures(root, serviceAccount: null));
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(30), $"took {started.Elapsed}: it walked the drive");
    }

    private static string Long(string path) => @"\\?\" + path;
}

/// <summary>
/// <see cref="FileObjects"/>' handle-based primitives on a real volume: what makes the takeover safe while
/// someone else can still write the directory, shown one property at a time.
/// </summary>
public sealed class FileObjectsOnDiskTests : IDisposable
{
    private readonly List<string> _made = [];

    // Newest first, so a junction goes before the directory it points to.
    public void Dispose() => Enumerable.Reverse(_made).ToList().ForEach(PlantedTree.Remove);

    private string NewDirectory()
    {
        var path = PlantedTree.UnderSystemDriveRoot();
        _made.Add(path);
        return path;
    }

    private static string Sddl(string path) =>
        (Directory.Exists(path)
            ? (FileSystemSecurity)new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner)
            : new FileInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner))
        .GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner);

    [ElevatedFact]
    public void Writing_a_directorys_security_changes_nothing_inside_it_so_a_hard_link_added_after_the_check_is_never_touched()
    {
        // SetSecurityInfo, which .NET's handle-based write calls, carries inheritable ACEs down to every child
        // before any has been judged: a hard link a user added after the scan had the file it shares a name
        // with -- in System32, say -- rewritten, and only then was refused.
        var path = NewDirectory();
        var elsewhere = NewDirectory();
        var original = Path.Combine(elsewhere, "original.dll");
        File.WriteAllText(original, "not windiag's");
        PlantedTree.HardLink(Path.Combine(path, "dbghelp.dll"), original);
        var before = Sddl(original);

        using (var held = FileObjects.Open(path, FileObjects.ReadControl | FileObjects.WriteDac | FileObjects.ReadAttributes, FileShare.ReadWrite | FileShare.Delete)!)
        {
            FileObjects.WriteSecurity(held, ProtectedAcl.DirectoryAcl(serviceAccount: null, ownedByAdministrators: false).GetSecurityDescriptorBinaryForm(), withOwner: false, protectedDacl: true, path);
        }

        Assert.True(new DirectoryInfo(path).GetAccessControl().AreAccessRulesProtected);
        Assert.Equal(before, Sddl(original));
    }

    [ElevatedFact]
    public void A_child_is_listed_and_opened_in_the_directory_held_even_after_its_path_is_made_to_lead_elsewhere()
    {
        // What a user does to a directory of theirs between its check and its walk: move it aside and put a
        // junction to somewhere else at its name. Listing or opening by path would follow the junction.
        var path = NewDirectory();
        File.WriteAllText(Path.Combine(path, "mine.txt"), "judged");
        var elsewhere = NewDirectory();
        File.WriteAllText(Path.Combine(elsewhere, "theirs.txt"), "not judged");

        using var held = FileObjects.Open(path, FileObjects.ListDirectory | FileObjects.ReadAttributes | FileObjects.Synchronize, FileShare.ReadWrite | FileShare.Delete)!;
        Directory.Move(path, path + ".moved");
        _made.Add(path + ".moved");
        PlantedTree.LinkDirectory(path, elsewhere);

        Assert.Equal(["mine.txt"], FileObjects.Children(held, path));
        using (var mine = FileObjects.OpenChild(held, "mine.txt", FileObjects.ReadAttributes, FileShare.ReadWrite | FileShare.Delete, path))
        {
            Assert.NotNull(mine);
        }

        Assert.Null(FileObjects.OpenChild(held, "theirs.txt", FileObjects.ReadAttributes, FileShare.ReadWrite | FileShare.Delete, path));

        // And the object itself, opened again through the handle, is still the directory that was judged.
        using var again = FileObjects.OpenChild(held, string.Empty, FileObjects.ListDirectory | FileObjects.ReadAttributes, FileShare.ReadWrite | FileShare.Delete, path)!;
        Assert.False(FileObjects.Inspect(again, path).IsLink);
        Assert.Equal(["mine.txt"], FileObjects.Children(again, path));
    }

    [ElevatedFact]
    public void Creating_a_directory_that_is_already_there_says_so_and_leaves_it_as_it_was()
    {
        // .NET's CreateDirectory with an ACL returns quietly over an existing directory: one a user made in the
        // moment before passed as the restricted one asked for, and stayed theirs.
        var path = NewDirectory();
        var before = Sddl(path);
        var descriptor = ProtectedAcl.DirectoryAcl(serviceAccount: null, ownedByAdministrators: true).GetSecurityDescriptorBinaryForm();

        Assert.False(FileObjects.CreateDirectory(path, descriptor));
        Assert.Equal(before, Sddl(path));

        var made = Path.Combine(path, "made");
        Assert.True(FileObjects.CreateDirectory(made, descriptor));
        Assert.True(new DirectoryInfo(made).GetAccessControl().AreAccessRulesProtected);
    }
}

/// <summary>The parts of <see cref="FileObjects"/> that are arithmetic on strings and buffers, and so run anywhere.</summary>
public sealed class FileObjectsFormatTests
{
    [Theory]
    [InlineData(@"C:\WinDiag", @"\\?\C:\WinDiag")]
    [InlineData(@"\\server\C$\WinDiag", @"\\?\UNC\server\C$\WinDiag")]
    [InlineData(@"\\?\C:\WinDiag", @"\\?\C:\WinDiag")]
    public void A_full_path_is_given_the_prefix_that_lifts_max_path_once(string path, string expected) =>
        Assert.Equal(expected, FileObjects.Extended(path));

    [Fact]
    public void Reads_every_name_in_a_listing_buffer_and_leaves_out_the_dot_entries()
    {
        var buffer = new byte[1024];
        var offset = 0;
        var names = new[] { ".", "..", "handle64.exe", "self-update.cmd" };
        for (var i = 0; i < names.Length; i++)
        {
            var name = System.Text.Encoding.Unicode.GetBytes(names[i]);
            var size = (68 + name.Length + 7) & ~7;
            BitConverter.GetBytes(i == names.Length - 1 ? 0 : size).CopyTo(buffer, offset);
            BitConverter.GetBytes(name.Length).CopyTo(buffer, offset + 60);
            name.CopyTo(buffer, offset + 68);
            offset += size;
        }

        Assert.Equal(["handle64.exe", "self-update.cmd"], FileObjects.EntryNames(buffer));
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

/// <summary>
/// A local account made for one test, and deleted after it: an individual administrator, or an ordinary
/// user, to own a directory the way one made on a real machine is owned.
/// </summary>
internal sealed class TemporaryLocalUser : IDisposable
{
    public TemporaryLocalUser(bool administrator)
    {
        // At most 20 characters, the SAM's limit for a name. The password is at most 14 so net user does not
        // stop to ask whether to accept one older systems cannot use, and meets the default complexity rule.
        Name = $"wdt{Guid.NewGuid():N}"[..15];
        var password = "Aa1!" + Guid.NewGuid().ToString("N")[..10];
        PlantedTree.Cmd($"net user {Name} {password} /add");
        try
        {
            Sid = (SecurityIdentifier)new NTAccount(Environment.MachineName, Name).Translate(typeof(SecurityIdentifier));
            if (administrator)
            {
                // By its localised name, looked up from the SID, as the server looks the group up.
                var group = ProtectedAcl.Administrators.Translate(typeof(NTAccount)).Value.Split('\\')[^1];
                PlantedTree.Cmd($"net localgroup \"{group}\" {Name} /add");
            }
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    public string Name { get; }

    public SecurityIdentifier Sid { get; private set; } = null!;

    public void Dispose() => PlantedTree.Cmd($"net user {Name} /delete");
}
