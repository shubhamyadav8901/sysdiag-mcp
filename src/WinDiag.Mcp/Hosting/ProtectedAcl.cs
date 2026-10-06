using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

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

    /// <summary>
    /// Who other than SYSTEM, Administrators and <paramref name="serviceAccount"/> can write the directory
    /// or anything in it, and anything in it that is a link.
    /// </summary>
    /// <remarks>
    /// <para>The contents count, not only the directory: a file or folder made while the directory was
    /// writable keeps its owner through any change to the directory's ACL, and an owner can always grant
    /// itself write access again. A <c>self-update.cmd</c> a user made, or a Microsoft-signed
    /// <c>handle64.exe</c> they own, would otherwise pass as protected.</para>
    /// <para>Refuses the directory outright when it, or a directory above it, is a link: see
    /// <see cref="RefuseLinks"/>.</para>
    /// </remarks>
    /// <exception cref="ConfigurationException">The directory is, or is reached through, a link.</exception>
    public static IReadOnlyList<string> DirectoryExposures(string path, SecurityIdentifier? serviceAccount)
    {
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        RefuseLinks(full);

        var trusted = Trusted(serviceAccount);
        var found = Exposures(
            new DirectoryInfo(full).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner),
            DirectoryWriteRights, trusted, "write to").ToList();

        foreach (var item in Contents(full))
        {
            found.AddRange(ItemExposures(item.FullName, trusted));
        }

        // A directory full of planted files would otherwise produce a refusal nobody can read to the end.
        const int shown = 10;
        return found.Count <= shown ? found : [.. found.Take(shown), $"and {found.Count - shown} more"];
    }

    /// <summary>Who else can change one item, judged through a handle on the item itself; a link counts.</summary>
    /// <remarks>
    /// An item this account cannot read the ACL of counts too, as unknown rather than safe: the repair then
    /// tries it and names it if that fails as well.
    /// </remarks>
    private static IEnumerable<string> ItemExposures(string path, IReadOnlyCollection<SecurityIdentifier> trusted)
    {
        SafeFileHandle? handle;
        try
        {
            handle = FileObjects.Open(path, FileObjects.ReadControl | FileObjects.ReadAttributes, FileShare.ReadWrite | FileShare.Delete);
        }
        catch (UnauthorizedAccessException)
        {
            return [$"{path} cannot be read by this account, so who can change it is unknown"];
        }

        if (handle is null)
        {
            // Gone since the listing.
            return [];
        }

        using (handle)
        {
            var node = FileObjects.Inspect(handle, path);
            if (node.IsLink)
            {
                return [$"{path} is a link, which windiag never puts in its directories"];
            }

            if (node.IsHardLink)
            {
                return [$"{path} is a hard link, the same file as one elsewhere, which windiag never makes"];
            }

            return Exposures(FileObjects.ReadAcl(handle, node.IsDirectory), DirectoryWriteRights, trusted, "write to")
                .Select(e => $"{path}: {e}").ToList();
        }
    }

    /// <summary>Everything under <paramref name="directory"/>, hidden and system items included, not looking inside links.</summary>
    /// <remarks>
    /// Walked by hand rather than with <see cref="EnumerationOptions.RecurseSubdirectories"/>, so whether a
    /// link is followed is decided here and not by the runtime. A link is returned, never entered.
    /// </remarks>
    private static IEnumerable<FileSystemInfo> Contents(string directory)
    {
        foreach (var item in new DirectoryInfo(directory).EnumerateFileSystemInfos("*", AllEntries))
        {
            yield return item;
            if (item is DirectoryInfo && !item.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                foreach (var nested in Contents(item.FullName))
                {
                    yield return nested;
                }
            }
        }
    }

    // Nothing skipped: the default skips hidden and system items, which a planted file can simply be.
    private static readonly EnumerationOptions AllEntries = new() { AttributesToSkip = 0, IgnoreInaccessible = false };

    /// <summary>
    /// Refuses <paramref name="path"/> when it, or any directory above it short of the drive root, is a
    /// reparse point: a junction, a symbolic link, or a folder a volume is mounted at.
    /// </summary>
    /// <remarks>
    /// <para>Every API that reads or sets an ACL by path resolves a link, so restricting a junction
    /// restricts wherever it points, and the junction itself stays its maker's. They can point it
    /// somewhere else as soon as the check is done -- after the service has been told the directory is
    /// safe -- and the SCM then starts whatever image is there as SYSTEM, or update_self writes and runs
    /// its helper there. <c>C:\</c> lets any user create a folder, so a <c>C:\WinDiag</c> may be exactly
    /// that, waiting for an administrator to install into it.</para>
    /// <para>A link above the directory is the same thing one level up. Reading attributes by path does
    /// not follow the last component, so each one is judged as itself.</para>
    /// </remarks>
    /// <exception cref="ConfigurationException">A link was found.</exception>
    internal static void RefuseLinks(string path)
    {
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        foreach (var component in Components(full))
        {
            FileAttributes attributes;
            try
            {
                attributes = File.GetAttributes(component);
            }
            catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
            {
                // Not there yet, and so nothing below it is either.
                return;
            }

            if (attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw LinkRefusal(component, full);
            }
        }
    }

    /// <summary>The directories from the one below the drive root down to <paramref name="full"/>, in that order.</summary>
    private static List<string> Components(string full)
    {
        var root = Path.GetPathRoot(full);
        var components = new List<string>();
        for (var current = full; !string.IsNullOrEmpty(current) && !string.Equals(
                 Path.TrimEndingDirectorySeparator(current), Path.TrimEndingDirectorySeparator(root ?? string.Empty),
                 StringComparison.OrdinalIgnoreCase);
             current = Path.GetDirectoryName(current))
        {
            components.Add(current);
        }

        components.Reverse();
        return components;
    }

    private static ConfigurationException LinkRefusal(string link, string full) => new(
        $"{link} is a link -- a junction, a symbolic link or a mounted folder"
        + (string.Equals(link, full, StringComparison.OrdinalIgnoreCase) ? string.Empty : $", and {full} is reached through it")
        + ". Whoever made it can point it somewhere else once it has been checked, and the service would then run, "
        + "or write, whatever is there. Nothing was changed. Give windiag a directory of its own that no link leads to, "
        + @"such as C:\WinDiag and C:\WinDiagArtifacts.");

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
    /// <para>Except when <paramref name="ownedByAdministrators"/> is false: a service running as
    /// NetworkService or LocalService cannot assign that owner, so the owner is left as it is. The
    /// exposure check still names an owner who is not trusted, so this cannot pass one off as safe.</para>
    /// </remarks>
    internal static DirectorySecurity DirectoryAcl(SecurityIdentifier? serviceAccount, bool ownedByAdministrators)
    {
        var acl = new DirectorySecurity();
        if (ownedByAdministrators)
        {
            // Only a modified section is written, so without this call the owner is not touched at all.
            acl.SetOwner(Administrators);
        }

        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        const InheritanceFlags everything = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        acl.AddAccessRule(new FileSystemAccessRule(LocalSystem, FileSystemRights.FullControl, everything, PropagationFlags.None, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, everything, PropagationFlags.None, AccessControlType.Allow));

        if (serviceAccount is not null && serviceAccount != LocalSystem)
        {
            acl.AddAccessRule(ServiceAccountRule(serviceAccount));
        }

        return acl;
    }

    /// <summary>The ACE <see cref="DirectoryAcl"/> gives a service account other than SYSTEM.</summary>
    internal static FileSystemAccessRule ServiceAccountRule(SecurityIdentifier serviceAccount) =>
        new(serviceAccount, FileSystemRights.Modify, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow);

    /// <summary>Whether <paramref name="security"/> already lets the service account modify the directory and what it holds.</summary>
    internal static bool GrantsServiceAccount(CommonObjectSecurity security, SecurityIdentifier serviceAccount) =>
        security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>()
            .Any(rule => rule.AccessControlType == AccessControlType.Allow
                         && serviceAccount.Equals(rule.IdentityReference)
                         && (rule.FileSystemRights & FileSystemRights.Modify) == FileSystemRights.Modify
                         && rule.InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit)
                         && !rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly));

    /// <summary>Adds <see cref="ServiceAccountRule"/> to a directory's ACL, leaving everything else as it is.</summary>
    public static void GrantServiceAccount(string path, SecurityIdentifier serviceAccount)
    {
        var directory = new DirectoryInfo(path);
        var acl = directory.GetAccessControl(AccessControlSections.Access);
        acl.AddAccessRule(ServiceAccountRule(serviceAccount));
        directory.SetAccessControl(acl);
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

    /// <summary>
    /// Creates the directory if needed, gives it <see cref="DirectoryAcl"/>, and takes over everything
    /// already in it; refuses one that is, or is reached through, or holds, a link.
    /// </summary>
    /// <remarks>
    /// <para>Refuses a drive root: <c>C:\</c> itself lets every user create folders, so it always reads as
    /// exposed, and protecting it would lock every user out of the whole drive. A server belongs in a
    /// directory of its own.</para>
    /// <para>Each directory from below the root down is opened without following a link and checked, and
    /// the directory itself is held open, shared for reading only, until the work is done, and its ACL is
    /// written through that handle. A check by name alone would leave a moment in which whoever can still
    /// write it -- that is why it is being protected -- renames it and puts a junction in its place, and the
    /// ACL, and the takeover of its contents, would land on wherever that points: System32, say. Held this
    /// way, nobody can rename or delete it meanwhile. The directories above are checked but not held: one a user can rename lets
    /// them redirect the path at any time, before this or after it, which is a matter of where windiag is
    /// put rather than of this moment -- and holding one open needs the right to list it, which a
    /// NetworkService service has on its own directory but not on every directory above it.</para>
    /// <para>A directory that does not exist is created with the ACL already on it, not given it
    /// afterwards: in between it would inherit "Authenticated Users: Modify" from <c>C:\</c>, and a handle
    /// a user opened then keeps that access whatever the ACL later says. So is any directory above it that
    /// does not exist yet, restricted the same way: made with what its parent hands down -- under a drive
    /// root, "Authenticated Users: Modify" -- any user could rename it and put their own in its place,
    /// redirecting everything below it.</para>
    /// <para>What is already inside is taken over as tools/windiag-acl.ps1 does, one rule in two places:
    /// see <see cref="TakeOverContents"/>. The script cannot call this, because it runs before anything
    /// from this repository is on the target. It differs in one way, on the safe side: it cannot read a
    /// reparse tag, so it refuses a deduplicated or compressed file that this takes over.</para>
    /// </remarks>
    /// <exception cref="ConfigurationException">A drive root, a file, or a link.</exception>
    public static void ProtectDirectory(string path, SecurityIdentifier? serviceAccount, bool ownedByAdministrators)
    {
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (string.Equals(full, Path.TrimEndingDirectorySeparator(Path.GetPathRoot(full) ?? string.Empty), StringComparison.OrdinalIgnoreCase))
        {
            throw new ConfigurationException(
                $"{full} is the root of a drive, which every user can write to, and restricting it would lock "
                + "them out of the whole drive. Put WinDiag.Mcp.exe and its artifacts in directories of their "
                + @"own, such as C:\WinDiag and C:\WinDiagArtifacts.");
        }

        var acl = DirectoryAcl(serviceAccount, ownedByAdministrators);
        var write = FileObjects.ReadControl | FileObjects.WriteDac | (ownedByAdministrators ? FileObjects.WriteOwner : 0);
        SafeFileHandle? held = null;
        try
        {
            foreach (var component in Components(full))
            {
                // The directory itself is held for listing and shared for reading only: share modes bind
                // only an open that asks for data access, and no-one may open it to write -- to set a
                // reparse point on it -- or to rename or delete it while this works.
                var hold = string.Equals(component, full, StringComparison.OrdinalIgnoreCase);
                var access = hold ? FileObjects.ListDirectory | FileObjects.ReadAttributes | FileObjects.Synchronize | write : FileObjects.ReadAttributes;
                var share = hold ? FileShare.Read : FileShare.ReadWrite | FileShare.Delete;

                var handle = FileObjects.Open(component, access, share);
                if (handle is null)
                {
                    acl.CreateDirectory(component);
                    handle = FileObjects.Open(component, access, share)
                             ?? throw new DirectoryNotFoundException($"{component} was created and is gone again.");
                }

                try
                {
                    RequireDirectory(FileObjects.Inspect(handle, component), component, full);
                }
                catch
                {
                    handle.Dispose();
                    throw;
                }

                if (hold)
                {
                    held = handle;
                }
                else
                {
                    handle.Dispose();
                }
            }

            // Before anything is changed, so a directory holding a link is refused untouched. Checked again
            // item by item below, since until the directory is restricted its contents can still change.
            foreach (var item in Contents(full))
            {
                using var handle = FileObjects.Open(item.FullName, FileObjects.ReadAttributes, FileShare.ReadWrite | FileShare.Delete);
                if (handle is not null)
                {
                    RefuseToTakeOver(FileObjects.Inspect(handle, item.FullName), item.FullName);
                }
            }

            FileObjects.WriteAcl(held!, acl, isDirectory: true);

            // Judged again before it is entered: an owner who could still write it a moment ago may have
            // made it a mount point, and the ACL written through the handle went on the mount point itself.
            RequireDirectory(FileObjects.Inspect(held!, full), full, full);
            TakeOverContents(full, ownedByAdministrators);
        }
        finally
        {
            held?.Dispose();
        }
    }

    private static void RequireDirectory(FileObjects.Node node, string path, string full)
    {
        if (node.IsLink)
        {
            throw LinkRefusal(path, full);
        }

        if (!node.IsDirectory)
        {
            throw new ConfigurationException($"{path} is a file, not a directory. Nothing was changed.");
        }
    }

    /// <summary>
    /// Hands each item under <paramref name="directory"/> to Administrators and replaces its explicit ACEs
    /// with SYSTEM and Administrators, inheritance left on.
    /// </summary>
    /// <remarks>
    /// <para>Protecting the directory replaces only what its contents inherit. Each item keeps its owner
    /// and its explicit ACEs, and an owner can always grant itself write access again -- so a
    /// <c>self-update.cmd</c> or a signed <c>handle64.exe</c> a user made while the directory was writable
    /// would stay theirs to rewrite, under SYSTEM's nose.</para>
    /// <para>Inheritance stays on so a service account's ACE on the directory still reaches each item.
    /// Explicit rules are always added: a security object with none is .NET's null-DACL placeholder,
    /// which is written as "Everyone: Full Control".</para>
    /// <para>Each item is judged and written through one handle opened on the item itself, and a directory
    /// is judged again after its ACL is written and before it is entered: until then its owner could have
    /// made it a mount point. A directory is listed only after it is restricted, so nothing can be added to
    /// it between the listing and the reset.</para>
    /// <para>When <paramref name="ownedByAdministrators"/> is false -- a service account that cannot assign
    /// that owner -- owners are left, and the exposure check that follows names any that is not
    /// trusted.</para>
    /// </remarks>
    private static void TakeOverContents(string directory, bool ownedByAdministrators)
    {
        var access = FileObjects.ReadControl | FileObjects.WriteDac | FileObjects.ReadAttributes | FileObjects.Synchronize
                     | (ownedByAdministrators ? FileObjects.WriteOwner : 0);

        foreach (var item in new DirectoryInfo(directory).EnumerateFileSystemInfos("*", AllEntries))
        {
            SafeFileHandle? handle;
            try
            {
                handle = FileObjects.Open(item.FullName, access, FileShare.ReadWrite | FileShare.Delete);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new ConfigurationException(
                    $"{item.FullName} cannot be taken over by this account ({ex.Message}): its ACL shuts out even "
                    + "administrators, which nothing windiag makes does. Take it over and remove it as an administrator "
                    + $"(takeown /a /r /d y /f \"{item.FullName}\", then delete it), and run this again.");
            }

            if (handle is null)
            {
                // Gone since the listing: moved out by its owner. Nothing can take its place, since the
                // directory it was in is restricted now.
                continue;
            }

            using (handle)
            {
                var node = FileObjects.Inspect(handle, item.FullName);
                RefuseToTakeOver(node, item.FullName);

                if (!node.IsDirectory)
                {
                    FileObjects.WriteAcl(handle, ItemAcl(new FileSecurity(), InheritanceFlags.None, ownedByAdministrators), isDirectory: false);
                    continue;
                }

                FileObjects.WriteAcl(handle, ItemAcl(new DirectorySecurity(), InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, ownedByAdministrators), isDirectory: true);
                RefuseToTakeOver(FileObjects.Inspect(handle, item.FullName), item.FullName);
            }

            TakeOverContents(item.FullName, ownedByAdministrators);
        }
    }

    private static T ItemAcl<T>(T acl, InheritanceFlags inheritance, bool ownedByAdministrators)
        where T : FileSystemSecurity
    {
        if (ownedByAdministrators)
        {
            acl.SetOwner(Administrators);
        }

        acl.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
        acl.AddAccessRule(new FileSystemAccessRule(LocalSystem, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        return acl;
    }

    /// <summary>Throws for an item the takeover must not touch.</summary>
    /// <remarks>
    /// <para>A junction or symbolic link would carry the change to wherever it points. Refused rather than
    /// skipped: a link nobody expected is itself the warning.</para>
    /// <para>So would a hard link, less visibly: it is the same file as one elsewhere on the volume, and
    /// its ACL is that file's. A user can link any file they can read -- a System32 binary included --
    /// and taking it over would hand it to Administrators and, through inheritance, to the service's
    /// account. Nothing windiag writes has a second name.</para>
    /// </remarks>
    private static void RefuseToTakeOver(FileObjects.Node node, string path)
    {
        if (node.IsLink)
        {
            throw new ConfigurationException(
                $"{path} is a link, which windiag never puts in its directories. Nothing beneath it was changed; "
                + "remove it and run this again.");
        }

        if (node.IsHardLink)
        {
            throw new ConfigurationException(
                $"{path} is a hard link: the same file as one elsewhere on the volume, so restricting it would "
                + "restrict that one too. Windiag never makes one. Remove it and run this again.");
        }
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
