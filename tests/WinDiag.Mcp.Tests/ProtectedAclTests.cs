using System.Security.AccessControl;
using System.Security.Principal;
using WinDiag.Mcp.Hosting;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// Which ACEs make the service's directories and registry key unsafe, and that the ACL written in their
/// place has none of them.
/// </summary>
/// <remarks>
/// Built in memory rather than read from disk, so nothing here needs elevation or changes the machine;
/// tests/WinDiag.Mcp.OnTarget applies the same ACLs to a real directory and service key.
/// </remarks>
public sealed class ProtectedAclTests
{
    private static readonly SecurityIdentifier AuthenticatedUsers = new(WellKnownSidType.AuthenticatedUserSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier NetworkService = new(WellKnownSidType.NetworkServiceSid, null);
    private static readonly SecurityIdentifier CreatorOwner = new(WellKnownSidType.CreatorOwnerSid, null);

    private static DirectorySecurity Directory(params FileSystemAccessRule[] rules)
    {
        var acl = new DirectorySecurity();
        acl.SetOwner(ProtectedAcl.Administrators);
        foreach (var rule in rules)
        {
            acl.AddAccessRule(rule);
        }

        return acl;
    }

    private static FileSystemAccessRule Allow(SecurityIdentifier who, FileSystemRights rights, PropagationFlags propagation = PropagationFlags.None) =>
        new(who, rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, propagation, AccessControlType.Allow);

    private static IReadOnlyList<string> DirectoryExposures(DirectorySecurity acl, SecurityIdentifier? account = null) =>
        ProtectedAcl.Exposures(acl, ProtectedAcl.DirectoryWriteRights, ProtectedAcl.Trusted(account), "write to");

    [Fact]
    public void Finds_the_authenticated_users_modify_ace_a_folder_under_C_root_inherits()
    {
        // The default C:\ ACL hands every new top-level folder "Authenticated Users: Modify" -- the
        // bootstrap default C:\WinDiag included -- and the SYSTEM service runs handle64.exe from there.
        var exposures = DirectoryExposures(Directory(
            Allow(ProtectedAcl.LocalSystem, FileSystemRights.FullControl),
            Allow(AuthenticatedUsers, FileSystemRights.Modify),
            Allow(Users, FileSystemRights.ReadAndExecute)));

        var only = Assert.Single(exposures);
        Assert.Contains("Authenticated Users", only, StringComparison.Ordinal);
    }

    [Fact]
    public void Counts_appending_alone_because_it_is_enough_to_create_a_file()
    {
        // C:\ itself grants Users AppendData on the folder: "create folders". In the server directory that
        // is enough to drop a DLL or an executable the server will find before the real one.
        Assert.NotEmpty(DirectoryExposures(Directory(Allow(Users, FileSystemRights.AppendData | FileSystemRights.ReadAndExecute))));
    }

    [Fact]
    public void Ignores_inherit_only_aces_and_creator_owner_which_do_not_apply_to_the_directory_itself()
    {
        Assert.Empty(DirectoryExposures(Directory(
            Allow(ProtectedAcl.Administrators, FileSystemRights.FullControl),
            Allow(Users, FileSystemRights.Modify, PropagationFlags.InheritOnly),
            Allow(CreatorOwner, FileSystemRights.FullControl))));
    }

    [Fact]
    public void Counts_an_owner_who_is_not_an_administrator_because_an_owner_can_rewrite_the_acl()
    {
        // C:\ lets any user create a folder, so C:\WinDiag may have been made by somebody waiting for an
        // administrator to copy a server into it.
        var acl = Directory(Allow(ProtectedAcl.LocalSystem, FileSystemRights.FullControl));
        acl.SetOwner(Users);

        Assert.Contains(DirectoryExposures(acl), e => e.Contains("owns it", StringComparison.Ordinal));
    }

    [Fact]
    public void The_acl_written_to_a_directory_exposes_nothing_inherits_nothing_and_is_owned_by_administrators()
    {
        var acl = ProtectedAcl.DirectoryAcl(serviceAccount: null);

        Assert.Empty(DirectoryExposures(acl));

        // Protected, or the next inheritance pass from C:\ puts the Authenticated Users ACE straight back.
        Assert.True(acl.AreAccessRulesProtected);
        Assert.Equal(ProtectedAcl.Administrators, acl.GetOwner(typeof(SecurityIdentifier)));
        Assert.Equal(
            new HashSet<SecurityIdentifier> { ProtectedAcl.LocalSystem, ProtectedAcl.Administrators },
            acl.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                .Select(r => (SecurityIdentifier)r.IdentityReference).ToHashSet());
    }

    [Fact]
    public void Puts_a_service_account_other_than_system_on_its_own_directories_and_trusts_only_that_one()
    {
        // Left off, a NetworkService install could not start its own executable or write a dump.
        var acl = ProtectedAcl.DirectoryAcl(NetworkService);

        Assert.Contains(
            acl.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(),
            r => r.IdentityReference.Equals(NetworkService) && r.FileSystemRights.HasFlag(FileSystemRights.Modify));

        Assert.Empty(DirectoryExposures(acl, NetworkService));
        Assert.NotEmpty(DirectoryExposures(acl, account: null));
    }

    [Fact]
    public void Finds_users_able_to_read_the_service_key_and_the_key_acl_written_has_no_one_else()
    {
        // The Services key's ACL, which sc.exe hands every new service key: Users can read values,
        // Environment and its WINDIAG_TOKEN included.
        var inherited = new RegistrySecurity();
        inherited.SetOwner(ProtectedAcl.LocalSystem);
        inherited.AddAccessRule(new RegistryAccessRule(ProtectedAcl.LocalSystem, RegistryRights.FullControl, AccessControlType.Allow));
        inherited.AddAccessRule(new RegistryAccessRule(Users, RegistryRights.ReadKey, AccessControlType.Allow));

        var exposed = ProtectedAcl.Exposures(inherited, ProtectedAcl.KeyExposingRights, ProtectedAcl.Trusted(null), "read or change");
        Assert.Contains(exposed, e => e.Contains("Users", StringComparison.Ordinal));

        var written = ProtectedAcl.ServiceKeyAcl();
        written.SetOwner(ProtectedAcl.LocalSystem);
        Assert.Empty(ProtectedAcl.Exposures(written, ProtectedAcl.KeyExposingRights, ProtectedAcl.Trusted(null), "read or change"));
        Assert.True(written.AreAccessRulesProtected);
    }

    [Fact]
    public void Refuses_to_restrict_a_drive_root_rather_than_lock_every_user_out_of_the_drive()
    {
        // WinDiag.Mcp.exe dropped straight into C:\ makes C:\ its server directory, and C:\ always reads as
        // writable by users -- it is meant to be.
        var ex = Assert.Throws<ConfigurationException>(() => ProtectedAcl.ProtectDirectory(@"C:\", serviceAccount: null));

        Assert.Contains("root of a drive", ex.Message, StringComparison.Ordinal);
    }
}
