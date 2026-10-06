using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace WinDiag.Mcp.Hosting;

/// <summary>
/// Restricts the service's registry key and its directories to SYSTEM and Administrators, and reports
/// who else can reach one that is not.
/// </summary>
/// <remarks>
/// <para>Nothing set these before, and the defaults are not what they look like. <c>sc create</c> gives
/// the service key the Services key's ACL, under which every local user can read values -- including the
/// <c>Environment</c> value that holds the bearer token. A directory made at the root of <c>C:\</c> (the
/// bootstrap default, <c>C:\WinDiag</c>) inherits "Authenticated Users: Modify", so any local user could
/// plant <c>handle64.exe</c> or a replacement server beside a binary that runs them as SYSTEM, or edit
/// <c>self-update.cmd</c> in the artifact directory while the helper waits.</para>
/// <para>The DACL written is protected -- nothing inherited from the parent -- because removing the bad
/// ACE would not survive: the next inheritance pass from <c>C:\</c> brings it straight back.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class ProtectedAcl
{
    internal static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);

    internal static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    // NT SERVICE\TrustedInstaller owns Program Files and System32: the OS's own servicing account, which
    // can already replace the OS itself, so it adds nothing to what an administrator could do.
    internal static readonly SecurityIdentifier TrustedInstaller =
        new("S-1-5-80-956008885-3425522526-1101993487-2163447651-1013034063");

    // CREATOR OWNER only ever describes what a future child's creator gets; Windows ignores it on the
    // object itself, and that creator needed write access here to make the child in the first place.
    private static readonly SecurityIdentifier CreatorOwner = new(WellKnownSidType.CreatorOwnerSid, null);

    private const int GenericAll = 0x10000000;
    private const int GenericWrite = 0x40000000;
    private const int GenericRead = unchecked((int)0x80000000);

    /// <summary>Rights on a directory that let someone plant, replace or remove what the server runs.</summary>
    /// <remarks>
    /// Attribute writes are left out on purpose: they cannot put code anywhere, and counting them would
    /// refuse directories whose only oddity is harmless.
    /// </remarks>
    internal const int DirectoryWriteRights = GenericAll | GenericWrite | (int)(
        FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.DeleteSubdirectoriesAndFiles
        | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership);

    /// <summary>Rights on the service key that read the token, or rewrite the grants beside it.</summary>
    internal const int KeyExposingRights = GenericAll | GenericWrite | GenericRead | (int)(
        RegistryRights.QueryValues | RegistryRights.SetValue | RegistryRights.ChangePermissions | RegistryRights.TakeOwnership);

    /// <summary>The service's own key, where the SCM keeps its configuration and environment.</summary>
    public static string ServiceKeyPath(string serviceName) => $@"SYSTEM\CurrentControlSet\Services\{serviceName}";

    /// <summary>
    /// Everyone other than <paramref name="trusted"/> who holds any of <paramref name="rights"/> on the
    /// object, or owns it -- an owner can rewrite the DACL whatever it says.
    /// </summary>
    /// <remarks>
    /// Allow ACEs only. A deny ACE could narrow an allow in principle, but counting on one would make this
    /// an access-check reimplementation, and the cost of being conservative is a refusal that names the
    /// ACE, not a hole.
    /// </remarks>
    internal static IReadOnlyList<string> Exposures(
        CommonObjectSecurity security, int rights, IReadOnlyCollection<SecurityIdentifier> trusted, string verb)
    {
        ArgumentNullException.ThrowIfNull(security);
        ArgumentNullException.ThrowIfNull(trusted);

        var found = new List<string>();
        if (security.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner && !trusted.Contains(owner))
        {
            found.Add($"{Name(owner)} owns it, so can change who has access");
        }

        foreach (AccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow
                || rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)
                || rule.IdentityReference is not SecurityIdentifier sid
                || sid == CreatorOwner
                || trusted.Contains(sid))
            {
                continue;
            }

            var mask = rule switch
            {
                FileSystemAccessRule file => (int)file.FileSystemRights,
                RegistryAccessRule key => (int)key.RegistryRights,
                _ => 0
            };

            if ((mask & rights) != 0)
            {
                found.Add($"{Name(sid)} can {verb} it");
            }
        }

        return found.Distinct(StringComparer.Ordinal).ToList();
    }

    /// <summary>SYSTEM, Administrators, TrustedInstaller, and the service's own account when it is another.</summary>
    internal static IReadOnlyCollection<SecurityIdentifier> Trusted(SecurityIdentifier? serviceAccount) =>
        serviceAccount is null ? [LocalSystem, Administrators, TrustedInstaller] : [LocalSystem, Administrators, TrustedInstaller, serviceAccount];

    /// <summary>Who other than SYSTEM, Administrators and <paramref name="serviceAccount"/> can write the directory.</summary>
    public static IReadOnlyList<string> DirectoryExposures(string path, SecurityIdentifier? serviceAccount) =>
        Exposures(
            new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner),
            DirectoryWriteRights, Trusted(serviceAccount), "write to");

    /// <summary>Who other than SYSTEM and Administrators can read the token out of the service's key, or change it.</summary>
    public static IReadOnlyList<string> ServiceKeyExposures(string serviceName)
    {
        using var key = Registry.LocalMachine.OpenSubKey(
            ServiceKeyPath(serviceName), RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ReadPermissions)
            ?? throw new ConfigurationException($"The service '{serviceName}' has no registry key.");

        return Exposures(
            key.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner),
            KeyExposingRights, Trusted(null), "read or change");
    }

    /// <summary>
    /// The DACL for a server or artifact directory: SYSTEM and Administrators full control, the service's
    /// own account (when it is not SYSTEM) modify, nothing inherited, owned by Administrators.
    /// </summary>
    /// <remarks>
    /// <para>A non-SYSTEM service account must be on it, or a NetworkService install could neither
    /// start its own executable nor write a dump.</para>
    /// <para>Owned by Administrators rather than whoever made the directory: <c>C:\</c> lets any user
    /// create a folder, so <c>C:\WinDiag</c> may have been made by somebody waiting for an administrator
    /// to copy a server into it, and an owner can put back any ACE this removes.</para>
    /// </remarks>
    internal static DirectorySecurity DirectoryAcl(SecurityIdentifier? serviceAccount)
    {
        var acl = new DirectorySecurity();
        acl.SetOwner(Administrators);
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        const InheritanceFlags everything = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        acl.AddAccessRule(new FileSystemAccessRule(LocalSystem, FileSystemRights.FullControl, everything, PropagationFlags.None, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, everything, PropagationFlags.None, AccessControlType.Allow));

        if (serviceAccount is not null && serviceAccount != LocalSystem)
        {
            acl.AddAccessRule(new FileSystemAccessRule(serviceAccount, FileSystemRights.Modify, everything, PropagationFlags.None, AccessControlType.Allow));
        }

        return acl;
    }

    /// <summary>The service key's DACL: SYSTEM and Administrators full control, nothing inherited.</summary>
    internal static RegistrySecurity ServiceKeyAcl()
    {
        var acl = new RegistrySecurity();
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        acl.AddAccessRule(new RegistryAccessRule(LocalSystem, RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
        acl.AddAccessRule(new RegistryAccessRule(Administrators, RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
        return acl;
    }

    /// <summary>Creates the directory if needed and gives it <see cref="DirectoryAcl"/>.</summary>
    /// <remarks>
    /// Refuses a drive root: <c>C:\</c> itself lets every user create folders, so it always reads as
    /// exposed, and protecting it would lock every user out of the whole drive. A server belongs in a
    /// directory of its own.
    /// </remarks>
    public static void ProtectDirectory(string path, SecurityIdentifier? serviceAccount)
    {
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (string.Equals(full, Path.TrimEndingDirectorySeparator(Path.GetPathRoot(full) ?? string.Empty), StringComparison.OrdinalIgnoreCase))
        {
            throw new ConfigurationException(
                $"{full} is the root of a drive, which every user can write to, and restricting it would lock "
                + "them out of the whole drive. Put WinDiag.Mcp.exe and its artifacts in directories of their "
                + @"own, such as C:\WinDiag and C:\WinDiagArtifacts.");
        }

        Directory.CreateDirectory(full);
        new DirectoryInfo(full).SetAccessControl(DirectoryAcl(serviceAccount));
    }

    /// <summary>Gives the service's key <see cref="ServiceKeyAcl"/>, before the token is written to it.</summary>
    public static void ProtectServiceKey(string serviceName)
    {
        using var key = Registry.LocalMachine.OpenSubKey(
            ServiceKeyPath(serviceName), RegistryKeyPermissionCheck.ReadWriteSubTree,
            RegistryRights.ChangePermissions | RegistryRights.ReadPermissions)
            ?? throw new ConfigurationException($"The service '{serviceName}' has no registry key to protect.");

        key.SetAccessControl(ServiceKeyAcl());
    }

    /// <summary>The SID of an account in sc.exe's spelling, or null for LocalSystem.</summary>
    public static SecurityIdentifier? AccountSid(string account)
    {
        ArgumentNullException.ThrowIfNull(account);

        if (string.Equals(account, "LocalSystem", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        // sc.exe takes ".\user" for a local account; NTAccount does not, so name the machine instead.
        var name = account.StartsWith(@".\", StringComparison.Ordinal) ? $@"{Environment.MachineName}\{account[2..]}" : account;
        try
        {
            return (SecurityIdentifier)new NTAccount(name).Translate(typeof(SecurityIdentifier));
        }
        catch (IdentityNotMappedException)
        {
            throw new ConfigurationException($"--account '{account}' is not an account this machine knows.");
        }
    }

    private static string Name(SecurityIdentifier sid)
    {
        try
        {
            return sid.Translate(typeof(NTAccount)).Value;
        }
        catch (SystemException)
        {
            // Unmapped (a deleted account) or no domain controller to ask: the SID still names it exactly.
            return sid.Value;
        }
    }
}
