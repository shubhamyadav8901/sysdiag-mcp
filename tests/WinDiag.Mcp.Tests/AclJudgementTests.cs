using System.Globalization;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using WinDiag.Mcp.Hosting;
using static WinDiag.Mcp.Hosting.AclJudgement;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// Who can redirect a directory above windiag's, judged on the ACLs Windows actually ships, written out as data.
/// </summary>
/// <remarks>
/// <para>Plain strings and masks, no Windows security objects, so these run on any OS. Every earlier test of
/// this rule built its ACLs from .NET's objects and its trust from the same constant as the code, so none of
/// them could see that the TrustedInstaller SID was wrong; on CI's Windows runner, where C:\ is
/// TrustedInstaller's, every directory below it was refused, which on a real machine is every service's.</para>
/// <para>Each ACL is what icacls prints for the folder on a fresh install, ACE by ACE, with its mask as stored:
/// F is 0x1F01FF, M 0x1301BF, RX 0x1200A9, AD (create folders / append data) 0x4, WD (create files / write
/// data) 0x2; an inherit-only ACE often keeps generic rights, which Windows maps only when it is inherited.</para>
/// </remarks>
public sealed class AclJudgementTests
{
    private const string AuthenticatedUsers = "S-1-5-11";
    private const string Users = "S-1-5-32-545";
    private const string AllApplicationPackages = "S-1-15-2-1";
    private const string AllRestrictedApplicationPackages = "S-1-15-2-2";
    private const string OrdinaryUser = "S-1-5-21-1004336348-1177238915-682003330-1001";

    private const int FullControl = 0x1F01FF;
    private const int Modify = 0x1301BF;
    private const int ReadAndExecute = 0x1200A9;
    private const int CreateFolders = 0x4;
    private const int CreateFiles = 0x2;
    private const int GenericAll = 0x10000000;
    private const int GenericReadExecute = unchecked((int)0xA0000000);

    // SDDL "SDGXGWGR": DELETE, GENERIC_EXECUTE, GENERIC_WRITE, GENERIC_READ -- how a client volume root stores
    // "Authenticated Users: Modify" for subfolders and files.
    private const int InheritableModify = unchecked((int)0xE0010000);

    private const AceFlags Everything = AceFlags.ObjectInherit | AceFlags.ContainerInherit;
    private const AceFlags ChildrenOnly = Everything | AceFlags.InheritOnly;

    private static readonly IReadOnlySet<string> Trusted = Sids(AlwaysTrusted);

    /// <summary>
    /// A Windows 10/11 system volume root. icacls C:\ prints Administrators (OI)(CI)(F), SYSTEM (OI)(CI)(F),
    /// Users (OI)(CI)(RX), Authenticated Users (OI)(CI)(IO)(M) and Authenticated Users (AD); owned by
    /// TrustedInstaller, as CI's runner reported for its own C:\.
    /// </summary>
    private static readonly (string Owner, Ace[] Dacl) ClientVolumeRoot = (TrustedInstallerSid,
    [
        new(AdministratorsSid, FullControl, Everything),
        new(LocalSystemSid, FullControl, Everything),
        new(Users, ReadAndExecute, Everything),
        new(AuthenticatedUsers, InheritableModify, ChildrenOnly),
        new(AuthenticatedUsers, CreateFolders),
    ]);

    /// <summary>
    /// A Windows Server system volume root: SYSTEM and Administrators (OI)(CI)(F), Users (OI)(CI)(RX), Users
    /// (CI)(AD) -- folders, here and in every subfolder -- Users (CI)(IO)(WD), and CREATOR OWNER (OI)(CI)(IO)(F).
    /// </summary>
    private static readonly (string Owner, Ace[] Dacl) ServerVolumeRoot = (TrustedInstallerSid,
    [
        new(LocalSystemSid, FullControl, Everything),
        new(AdministratorsSid, FullControl, Everything),
        new(Users, ReadAndExecute, Everything),
        new(Users, CreateFolders, AceFlags.ContainerInherit),
        new(Users, CreateFiles, AceFlags.ContainerInherit | AceFlags.InheritOnly),
        new(CreatorOwnerSid, GenericAll, ChildrenOnly),
    ]);

    private static readonly Dictionary<string, (string Owner, Ace[] Dacl)> SystemFolders = new()
    {
        ["volume root, client"] = ClientVolumeRoot,
        ["volume root, server"] = ServerVolumeRoot,

        // SYSTEM and Administrators (OI)(CI)(F), Users (RX) and (OI)(CI)(IO)(GR,GE), Everyone the same.
        [@"C:\Users"] = (LocalSystemSid,
        [
            new(LocalSystemSid, FullControl, Everything),
            new(AdministratorsSid, FullControl, Everything),
            new(Users, ReadAndExecute),
            new(Users, GenericReadExecute, ChildrenOnly),
            new(EveryoneSid, ReadAndExecute),
            new(EveryoneSid, GenericReadExecute, ChildrenOnly),
        ]),

        // SYSTEM and Administrators (OI)(CI)(F), CREATOR OWNER (OI)(CI)(IO)(F), Users (OI)(CI)(RX), and Users
        // (CI)(WD,AD,WEA,WA): any user may create files and folders in ProgramData itself.
        [@"C:\ProgramData"] = (LocalSystemSid,
        [
            new(LocalSystemSid, FullControl, Everything),
            new(AdministratorsSid, FullControl, Everything),
            new(CreatorOwnerSid, GenericAll, ChildrenOnly),
            new(Users, ReadAndExecute, Everything),
            new(Users, CreateFiles | CreateFolders | 0x10 | 0x100, AceFlags.ContainerInherit),
        ]),

        // TrustedInstaller (F) and (CI)(IO)(F), SYSTEM and Administrators (M) and (OI)(CI)(IO)(F), Users and both
        // application-package groups (RX) and (OI)(CI)(IO)(GR,GE), CREATOR OWNER (OI)(CI)(IO)(F).
        [@"C:\Program Files"] = (TrustedInstallerSid,
        [
            new(TrustedInstallerSid, FullControl),
            new(TrustedInstallerSid, GenericAll, AceFlags.ContainerInherit | AceFlags.InheritOnly),
            new(LocalSystemSid, Modify),
            new(LocalSystemSid, GenericAll, ChildrenOnly),
            new(AdministratorsSid, Modify),
            new(AdministratorsSid, GenericAll, ChildrenOnly),
            new(Users, ReadAndExecute),
            new(Users, GenericReadExecute, ChildrenOnly),
            new(CreatorOwnerSid, GenericAll, ChildrenOnly),
            new(AllApplicationPackages, ReadAndExecute),
            new(AllApplicationPackages, GenericReadExecute, ChildrenOnly),
            new(AllRestrictedApplicationPackages, ReadAndExecute),
            new(AllRestrictedApplicationPackages, GenericReadExecute, ChildrenOnly),
        ]),
    };

    [Fact]
    public void The_trustedinstaller_sid_is_the_one_windows_derives_from_the_service_name()
    {
        // A service SID is S-1-5-80 and the SHA-1 of the upper-cased service name in UTF-16LE, as five
        // little-endian sub-authorities -- what sc showsid prints. The constant once had four of five wrong,
        // and Windows' own C:\ then read as a stranger's.
        var hash = SHA1.HashData(Encoding.Unicode.GetBytes("TrustedInstaller".ToUpperInvariant()));
        var derived = "S-1-5-80-" + string.Join("-", Enumerable.Range(0, 5).Select(i => BitConverter.ToUInt32(hash, i * 4).ToString(CultureInfo.InvariantCulture)));

        Assert.Equal(TrustedInstallerSid, derived);
    }

    [Theory]
    [InlineData("volume root, client")]
    [InlineData("volume root, server")]
    [InlineData(@"C:\Users")]
    [InlineData(@"C:\ProgramData")]
    [InlineData(@"C:\Program Files")]
    public void Nobody_but_the_system_can_rename_or_empty_a_folder_windows_ships_though_users_may_create_in_some(string folder)
    {
        // Above a windiag directory, what counts is who can take each folder away -- rename or delete it, or what
        // it holds, or rewrite its ACL -- not who can add to it: every user may make folders in C:\ and
        // ProgramData, and none of them can put their own C:\WinDiag in place of an administrator's.
        var (owner, dacl) = SystemFolders[folder];

        Assert.Empty(Holders(owner, dacl, ProtectedAcl.RenameRights, Trusted));
        Assert.Empty(Holders(owner, dacl, ProtectedAcl.RemoveChildRights, Trusted));
    }

    [Theory]
    [InlineData("volume root, client")]
    [InlineData(@"C:\Program Files")]
    public void A_folder_trustedinstaller_owns_passes_only_because_trustedinstaller_is_trusted(string folder)
    {
        // What CI's runner hit: with TrustedInstaller left out, its ownership -- and on Program Files its own full
        // control -- reads as somebody else's right to change the ACL, and everything below C:\ is refused.
        var (owner, dacl) = SystemFolders[folder];

        var holders = Holders(owner, dacl, ProtectedAcl.RemoveChildRights, Sids([LocalSystemSid, AdministratorsSid]));
        Assert.Contains(new Holder(TrustedInstallerSid, Owns: true), holders);
        Assert.All(holders, holder => Assert.Equal(TrustedInstallerSid, holder.Sid));
    }

    [Theory]
    [InlineData("volume root, client", AuthenticatedUsers)]
    [InlineData("volume root, server", Users)]
    public void A_server_copied_to_a_volume_root_reads_as_writable_by_every_user(string folder, string creator)
    {
        // The other side of the line: as the directory windiag runs from, being able to create in it is enough
        // to plant a DLL beside the server, and the root is refused for it.
        var (owner, dacl) = SystemFolders[folder];

        Assert.Equal([new Holder(creator, Owns: false)], Holders(owner, dacl, ProtectedAcl.DirectoryWriteRights, Trusted));
    }

    [Fact]
    public void A_folder_an_administrator_makes_under_a_client_volume_root_is_any_users_to_rename()
    {
        // C:\Lab as Windows makes it: the root's inherit-only "Authenticated Users: Modify" is now an ACE that
        // applies, and Modify carries DELETE. Anything below C:\Lab is anybody's to redirect.
        var dacl = new Ace[]
        {
            new(AdministratorsSid, FullControl, Everything | AceFlags.Inherited),
            new(LocalSystemSid, FullControl, Everything | AceFlags.Inherited),
            new(Users, ReadAndExecute, Everything | AceFlags.Inherited),
            new(AuthenticatedUsers, Modify, Everything | AceFlags.Inherited),
        };

        Assert.Equal([new Holder(AuthenticatedUsers, Owns: false)], Holders(AdministratorsSid, dacl, ProtectedAcl.RenameRights, Trusted));
    }

    [Fact]
    public void A_folder_an_ordinary_user_makes_under_a_server_volume_root_is_theirs_by_owning_it_and_by_creator_owner()
    {
        // CREATOR OWNER's inherit-only ACE on the root becomes the user's own full control on their folder, and
        // they own it besides; either alone lets them rename it.
        var dacl = new Ace[]
        {
            new(LocalSystemSid, FullControl, Everything | AceFlags.Inherited),
            new(AdministratorsSid, FullControl, Everything | AceFlags.Inherited),
            new(Users, ReadAndExecute, Everything | AceFlags.Inherited),
            new(Users, CreateFolders, AceFlags.ContainerInherit | AceFlags.Inherited),
            new(Users, CreateFiles, AceFlags.ContainerInherit | AceFlags.Inherited),
            new(OrdinaryUser, FullControl, AceFlags.Inherited),
            new(CreatorOwnerSid, GenericAll, ChildrenOnly | AceFlags.Inherited),
        };

        Assert.Equal(
            [new Holder(OrdinaryUser, Owns: true), new Holder(OrdinaryUser, Owns: false)],
            Holders(OrdinaryUser, dacl, ProtectedAcl.RenameRights, Trusted));
    }

    [Theory]
    [InlineData(0x40, false, true)]                         // FILE_DELETE_CHILD: removes what it holds, not it
    [InlineData(0x10000, true, false)]                      // DELETE: removes it, not what it holds
    [InlineData(0x40000, true, true)]                       // WRITE_DAC: grants itself either
    [InlineData(0x80000, true, true)]                       // WRITE_OWNER: takes it, then the same
    [InlineData(0x10000000, true, true)]                    // GENERIC_ALL
    [InlineData(CreateFolders | CreateFiles, false, false)] // creating alone takes nothing away
    [InlineData(ReadAndExecute, false, false)]
    public void Each_right_counts_for_renaming_a_folder_or_emptying_it_by_what_it_lets_a_user_take_away(int mask, bool renames, bool empties)
    {
        Ace[] dacl = [new(AdministratorsSid, FullControl, Everything), new(Users, mask)];

        Assert.Equal(renames, Holders(AdministratorsSid, dacl, ProtectedAcl.RenameRights, Trusted).Count > 0);
        Assert.Equal(empties, Holders(AdministratorsSid, dacl, ProtectedAcl.RemoveChildRights, Trusted).Count > 0);
    }

    [Fact]
    public void An_inherit_only_ace_a_deny_ace_and_creator_owner_grant_nothing_on_the_folder_itself()
    {
        Ace[] dacl =
        [
            new(AdministratorsSid, FullControl, Everything),
            new(Users, FullControl, ChildrenOnly),
            new(OrdinaryUser, FullControl, Allows: false),
            new(CreatorOwnerSid, FullControl),
        ];

        Assert.Empty(Holders(AdministratorsSid, dacl, ProtectedAcl.DirectoryWriteRights, Trusted));
    }

    [Fact]
    public void A_folder_with_no_dacl_at_all_is_everyones_while_an_empty_one_is_nobodys()
    {
        Assert.Equal([new Holder(EveryoneSid, Owns: false)], Holders(AdministratorsSid, dacl: null, ProtectedAcl.RenameRights, Trusted));
        Assert.Empty(Holders(AdministratorsSid, [], ProtectedAcl.RenameRights, Trusted));
    }

    [Fact]
    public void A_sid_is_matched_whatever_the_case_it_was_written_in() =>
        Assert.Empty(Holders(TrustedInstallerSid.ToLowerInvariant(), [], ProtectedAcl.RenameRights, Trusted));

    [Fact]
    public void The_bootstrap_script_trusts_the_same_accounts_and_counts_the_same_rights_as_the_server()
    {
        // tools/windiag-acl.ps1 judges the same directories before the server is on the target, and cannot
        // reference this code: it carried the same wrong SID, and refused the same C:\.
        var script = File.ReadAllText(BootstrapAclScriptTests.ScriptPath());

        var trusted = Regex.Match(script, @"^\s*\$trusted = (.+)$", RegexOptions.Multiline).Groups[1].Value;
        Assert.Equal(AlwaysTrusted, Regex.Matches(trusted, "'([^']+)'").Select(m => m.Groups[1].Value));

        foreach (var (name, rights) in new[]
                 {
                     ("directoryWriteRights", ProtectedAcl.DirectoryWriteRights),
                     ("renameRights", ProtectedAcl.RenameRights),
                     ("removeChildRights", ProtectedAcl.RemoveChildRights),
                 })
        {
            var value = Regex.Match(script, $@"^\s*\${name} = 0x([0-9A-Fa-f]+)", RegexOptions.Multiline).Groups[1].Value;
            Assert.Equal(rights, int.Parse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture));
        }

        Assert.All(
            Regex.Matches(script, @"S-1-5-80-[0-9-]+").Select(m => m.Value),
            sid => Assert.Equal(TrustedInstallerSid, sid));
    }
}
