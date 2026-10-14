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
        var acl = ProtectedAcl.DirectoryAcl(serviceAccount: null, ownedByAdministrators: true);

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
        var acl = ProtectedAcl.DirectoryAcl(NetworkService, ownedByAdministrators: true);

        Assert.Contains(
            acl.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(),
            r => r.IdentityReference.Equals(NetworkService) && r.FileSystemRights.HasFlag(FileSystemRights.Modify));

        Assert.Empty(DirectoryExposures(acl, NetworkService));
        Assert.NotEmpty(DirectoryExposures(acl, account: null));
    }

    [Fact]
    public void The_acl_a_service_account_other_than_system_writes_leaves_the_owner_alone_since_it_cannot_assign_administrators()
    {
        // A NetworkService token has neither the Administrators group nor SeRestorePrivilege, so writing
        // Administrators as the owner fails -- and on the default artifact directory, made on the first
        // start, that refused every start of a NetworkService or LocalService install.
        var acl = ProtectedAcl.DirectoryAcl(NetworkService, ownedByAdministrators: false);

        Assert.Null(acl.GetOwner(typeof(SecurityIdentifier)));
        Assert.True(acl.AreAccessRulesProtected);
        Assert.Empty(DirectoryExposures(acl, NetworkService));
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
    public void The_token_key_acl_admits_only_system_administrators_and_a_service_account_that_must_read_it_itself()
    {
        // Unlike the Environment value, which the SCM reads as SYSTEM and hands over, the token key is read by
        // the service's own token: a NetworkService service shut out of it would start with a token nobody holds.
        foreach (var account in new SecurityIdentifier?[] { null, NetworkService })
        {
            var written = ProtectedAcl.TokenKeyAcl(account);
            written.SetOwner(ProtectedAcl.Administrators);

            Assert.True(written.AreAccessRulesProtected);
            Assert.Empty(ProtectedAcl.Exposures(written, ProtectedAcl.KeyExposingRights, ProtectedAcl.Trusted(account), "read or change"));
            Assert.All(
                written.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)).Cast<RegistryAccessRule>(),
                rule => Assert.Contains(rule.IdentityReference, new IdentityReference?[] { ProtectedAcl.LocalSystem, ProtectedAcl.Administrators, account }));
        }

        // And the NetworkService ACE reads, nothing more: it may not rewrite the ACL or the token.
        var rule = ProtectedAcl.TokenKeyAcl(NetworkService)
            .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)).Cast<RegistryAccessRule>()
            .Single(r => r.IdentityReference.Equals(NetworkService));
        Assert.Equal(RegistryRights.ReadKey, rule.RegistryRights);

        // Judged as a LocalSystem install, the same ACE would be somebody else's.
        Assert.NotEmpty(ProtectedAcl.Exposures(ProtectedAcl.TokenKeyAcl(NetworkService), ProtectedAcl.KeyExposingRights, ProtectedAcl.Trusted(null), "read or change"));
    }

    [Theory]
    [InlineData(@"NT AUTHORITY\NetworkService", "S-1-5-20")]
    [InlineData(@"NT AUTHORITY\LocalService", "S-1-5-19")]
    [InlineData("networkservice", "S-1-5-20")]
    public void Resolves_the_built_in_service_accounts_without_asking_lsa_for_a_name_it_does_not_know(string account, string sid)
    {
        // LookupAccountName does not resolve the sc.exe spelling, as Microsoft's account pages say; looked up by
        // name, every NetworkService and LocalService install was refused before sc.exe ran.
        Assert.Equal(new SecurityIdentifier(sid), ProtectedAcl.AccountSid(account));
    }

    [Fact]
    public void Resolves_local_system_to_no_account_of_its_own_as_the_rest_of_the_installer_expects()
    {
        Assert.Null(ProtectedAcl.AccountSid("LocalSystem"));
    }

    [Fact]
    public void Refuses_to_restrict_a_drive_root_rather_than_lock_every_user_out_of_the_drive()
    {
        // WinDiag.Mcp.exe dropped straight into C:\ makes C:\ its server directory, and C:\ always reads as
        // writable by users -- it is meant to be.
        var ex = Assert.Throws<ConfigurationException>(() => ProtectedAcl.ProtectDirectory(@"C:\", serviceAccount: null, ownedByAdministrators: true));

        Assert.Contains("root of a drive", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_admin_only_directory_does_not_yet_grant_a_network_service_account_and_its_own_acl_does()
    {
        // The case the installer must not skip: the bootstrap scripts leave C:\WinDiag restricted to SYSTEM and
        // Administrators, which reads as "not exposed", yet a NetworkService service could not start from it.
        var networkService = new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null);
        var adminOnly = ProtectedAcl.DirectoryAcl(serviceAccount: null, ownedByAdministrators: true);

        Assert.False(ProtectedAcl.GrantsServiceAccount(adminOnly, networkService));
        Assert.True(ProtectedAcl.GrantsServiceAccount(ProtectedAcl.DirectoryAcl(networkService, ownedByAdministrators: true), networkService));

        adminOnly.AddAccessRule(ProtectedAcl.ServiceAccountRule(networkService));
        Assert.True(ProtectedAcl.GrantsServiceAccount(adminOnly, networkService));
    }

    [Fact]
    public void A_takeover_a_service_account_may_not_do_is_not_blamed_on_an_acl_that_shuts_out_administrators()
    {
        // A NetworkService service is denied WRITE_DAC on every file an administrator deployed: the account may
        // modify it but only its owner may change its ACL. Told the item's ACL shuts out administrators, and to
        // take it over and delete it, the operator would have been sent to remove WinDiag.Mcp.exe itself.
        var item = @"C:\WinDiag\WinDiag.Mcp.exe";

        var asService = ProtectedAcl.TakeOverRefusal(item, "Access is denied.", ownedByAdministrators: false);
        var asAdministrator = ProtectedAcl.TakeOverRefusal(item, "Access is denied.", ownedByAdministrators: true);

        Assert.DoesNotContain("shuts out even administrators", asService, StringComparison.Ordinal);
        Assert.DoesNotContain("takeown", asService, StringComparison.Ordinal);
        Assert.Contains("--install-service", asService, StringComparison.Ordinal);
        Assert.Contains("shuts out even administrators", asAdministrator, StringComparison.Ordinal);
        Assert.Contains($"takeown /a /r /d y /f \"{item}\"", asAdministrator, StringComparison.Ordinal);
    }

    [Fact]
    public void A_directory_above_that_others_can_change_is_refused_with_how_to_hand_its_ownership_to_administrators()
    {
        // Already restricted by hand but owned by an account outside the group, it was refused with "restrict
        // it to administrators" -- which the operator had done -- and the owner, the actual cause, unnamed.
        var remedy = ProtectedAcl.RedirectRemedy(@"D:\Ops");

        Assert.Contains(@"icacls ""D:\Ops"" /setowner *S-1-5-32-544", remedy, StringComparison.Ordinal);
        Assert.Contains("direct member of the local Administrators group", remedy, StringComparison.Ordinal);
    }
}

/// <summary>
/// What <see cref="ProtectedAcl.CreateKeyWithAcl"/> leaves in the real registry: the token key's ACL from the moment
/// it exists, which nothing built in memory can show.
/// </summary>
/// <remarks>Elevated Windows only, as the installer is: CI's Windows runner. Each test removes its scratch key.</remarks>
public sealed class TokenKeyOnRegistryTests : IDisposable
{
    private static readonly SecurityIdentifier NetworkService = new(WellKnownSidType.NetworkServiceSid, null);

    private readonly string _name = $"windiag-test-{Guid.NewGuid():N}";

    public void Dispose()
    {
        if (OperatingSystem.IsWindows() && new ElevatedFactAttribute().Skip is null)
        {
            using var software = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("SOFTWARE", writable: true);
            software?.DeleteSubKeyTree(_name, throwOnMissingSubKey: false);
        }
    }

    [ElevatedFact]
    public void Creates_the_key_protected_owned_by_administrators_and_readable_by_the_service_account_from_the_start()
    {
        // .NET's CreateSubKey overload that takes a RegistrySecurity discards it: the key came out inheriting
        // its parent's ACL, with no ACE for a NetworkService service, which then could not read its own token.
        var acl = ProtectedAcl.TokenKeyAcl(NetworkService);
        acl.SetOwner(ProtectedAcl.Administrators);
        using var software = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("SOFTWARE", writable: true)!;

        using (var key = ProtectedAcl.CreateKeyWithAcl(software, _name, acl))
        {
            Assert.NotNull(key);
            var written = key.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);

            Assert.True(written.AreAccessRulesProtected);
            Assert.Equal(ProtectedAcl.Administrators, written.GetOwner(typeof(SecurityIdentifier)));
            Assert.Contains(
                written.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)).Cast<RegistryAccessRule>(),
                r => r.IdentityReference.Equals(NetworkService) && r.RegistryRights == RegistryRights.ReadKey);
            Assert.Empty(ProtectedAcl.Exposures(written, ProtectedAcl.KeyExposingRights, ProtectedAcl.Trusted(NetworkService), "read or change"));
        }

        // One already there is opened as it is by RegCreateKeyEx, whatever descriptor is passed: refused, not used.
        Assert.Null(ProtectedAcl.CreateKeyWithAcl(software, _name, acl));
    }
}
