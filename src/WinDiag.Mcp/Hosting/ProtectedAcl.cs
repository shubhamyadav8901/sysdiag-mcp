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
    /// <see cref="Trusted"/>, and every direct member of the local Administrators group: who may own or change
    /// a directory above a server or artifact directory.
    /// </summary>
    /// <remarks>
    /// <para>Wider than for the directory itself because windiag never changes the directories above, so
    /// nothing it does can repair one. A <c>D:\Ops</c> locked to administrators by hand but made by the
    /// built-in Administrator account is owned by that account, not the group, and under the group alone it
    /// read as anybody's to rename: the service refused every start after update_self, which has no way
    /// back. A member of the group can elevate and do anything SYSTEM can. What this gives up is that the
    /// member's unelevated programs, which carry its own SID, could rename such a directory too -- a way
    /// around UAC, which Microsoft does not hold to be a security boundary, and not a way in for anyone
    /// who is not already an administrator.</para>
    /// <para>Not for the directory itself or what it holds: those windiag restricts, and an ACE or owner that
    /// is a user's own SID is also usable from that user's unelevated programs, which it costs nothing to
    /// shut out there. See <see cref="LocalAdministrators"/> for why members reached through a domain group
    /// are not counted.</para>
    /// </remarks>
    internal static IReadOnlyCollection<SecurityIdentifier> TrustedAbove(SecurityIdentifier? serviceAccount) =>
        [.. Trusted(serviceAccount).Union(LocalAdministrators.Members())];

    /// <summary>Rights over a directory that let someone rename or remove it, or give themselves that right.</summary>
    internal const int RenameRights = GenericAll | (int)(
        FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership);

    /// <summary>Rights over a directory that let someone rename or remove what it holds, whatever that says.</summary>
    internal const int RemoveChildRights = GenericAll | (int)(
        FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership);

    // What others may do while an item is open to be judged or taken over: anything, since the handle, not
    // the name, is what is judged; refusing them would only turn a held file into a failed start.
    private const FileShare Shared = FileShare.ReadWrite | FileShare.Delete;

    private const int SharingViolation = unchecked((int)0x80070020);

    /// <summary>
    /// Who other than SYSTEM, Administrators and <paramref name="serviceAccount"/> can write the directory
    /// or anything in it, or rename a directory on the way to it and put their own in its place.
    /// </summary>
    /// <remarks>
    /// <para>The contents count, not only the directory: a file or folder made while the directory was
    /// writable keeps its owner through any change to the directory's ACL, and an owner can always grant
    /// itself write access again. A <c>self-update.cmd</c> a user made, or a Microsoft-signed
    /// <c>handle64.exe</c> they own, would otherwise pass as protected.</para>
    /// <para>So do the directories above it: see <see cref="RenameRights"/> and <see cref="RemoveChildRights"/>.
    /// One whose ACL this account may not read is skipped, not passed off as judged: a service account is
    /// not let read every directory above its own -- <c>C:\Windows\ServiceProfiles</c> is administrators'
    /// alone -- and refusing that would stop such a service on every start. The installer runs elevated,
    /// and reads them.</para>
    /// <para>A link or hard link inside counts only when someone else can change it, judged by its own ACL,
    /// and is never entered. One only administrators can change -- Git for Windows' hard links, or a
    /// junction an administrator made -- is theirs to have made, and refusing it stopped services that had
    /// started for years. Taking over a directory others can write is another matter: see
    /// <see cref="RefuseToTakeOver"/>.</para>
    /// <para>Each item is judged through a handle opened relative to its parent's, so a name made to lead
    /// elsewhere between the listing and the look is never followed. An item this account may not read is
    /// counted as unknown rather than safe: the repair then tries it, and names it if that fails too.</para>
    /// <para>Refuses the directory outright when it, or a directory above it, is a link: see
    /// <see cref="RefuseLinks"/>.</para>
    /// </remarks>
    /// <exception cref="ConfigurationException">The directory is, or is reached through, a link.</exception>
    public static IReadOnlyList<string> DirectoryExposures(string path, SecurityIdentifier? serviceAccount)
    {
        var full = FullPath(path);
        RefuseLinks(full);

        var trusted = Trusted(serviceAccount);
        var above = TrustedAbove(serviceAccount);
        var found = new List<string>();
        var parentPath = Path.GetPathRoot(full)!;
        FileSystemSecurity? parent = null;

        // A drive root has nothing above it, and is judged as the directory itself: a server copied to C:\
        // must read as exposed, as C:\ is, and not as a path with no directories on it to judge.
        var components = Components(full);
        var atRoot = components.Count == 0;
        if (atRoot)
        {
            components.Add(full);
        }
        else
        {
            using (OpenOnTheWay(parentPath, full, FileObjects.ReadAttributes, aclOptional: true, out parent))
            {
            }
        }

        foreach (var component in components)
        {
            var isTarget = Same(component, full);
            using var handle = OpenOnTheWay(component, full, FileObjects.ReadAttributes, aclOptional: !isTarget, out var own)
                               ?? throw new DirectoryNotFoundException($"{component} does not exist.");

            if (parent is not null)
            {
                found.AddRange(Exposures(parent, RemoveChildRights, above, "remove what is in")
                    .Select(e => $"{parentPath}, which holds {component}: {e}"));
            }

            if (!isTarget)
            {
                if (own is not null)
                {
                    found.AddRange(Exposures(own, RenameRights, above, "rename or remove")
                        .Select(e => $"{component}, on the way to it: {e}"));
                }

                parentPath = component;
                parent = own;
                continue;
            }

            found.AddRange(Exposures(own!, DirectoryWriteRights, trusted, "write to"));
            if (atRoot)
            {
                // A drive root: every user can make folders in it, and walking the whole drive to say more
                // would only delay the refusal ProtectDirectory gives a root anyway.
                continue;
            }

            var listing = OpenListing(handle, full, out var whyNot);
            if (listing is null)
            {
                found.Add($"{full}: what it holds cannot be listed by this account ({whyNot ?? "it is being deleted"}), so who can change that is unknown");
                continue;
            }

            using (listing)
            {
                ContentExposures(listing, full, trusted, found);
            }
        }

        // A directory full of planted files would otherwise produce a refusal nobody can read to the end.
        const int shown = 10;
        return found.Count <= shown ? found : [.. found.Take(shown), $"and {found.Count - shown} more"];
    }

    /// <summary>Adds to <paramref name="found"/> who else can change each item the listed directory holds, at any depth.</summary>
    private static void ContentExposures(
        SafeFileHandle listing, string path, IReadOnlyCollection<SecurityIdentifier> trusted, List<string> found)
    {
        foreach (var name in FileObjects.Children(listing, path))
        {
            var itemPath = Path.Join(path, name);
            SafeFileHandle? item;
            try
            {
                item = FileObjects.OpenChild(listing, name, FileObjects.ReadControl | FileObjects.ReadAttributes, Shared, itemPath);
            }
            catch (UnauthorizedAccessException)
            {
                found.Add($"{itemPath} cannot be read by this account, so who can change it is unknown");
                continue;
            }

            if (item is null)
            {
                // Gone since the listing.
                continue;
            }

            using (item)
            {
                var node = FileObjects.Inspect(item, itemPath);
                var exposures = Exposures(FileObjects.ReadAcl(item, node.IsDirectory), DirectoryWriteRights, trusted, "write to");
                if (node.IsLink || node.IsHardLink)
                {
                    if (exposures.Count > 0)
                    {
                        found.Add($"{itemPath} is a {(node.IsLink ? "link" : "hard link")}, and {string.Join(", and ", exposures)}");
                    }

                    continue;
                }

                found.AddRange(exposures.Select(e => $"{itemPath}: {e}"));
                if (!node.IsDirectory)
                {
                    continue;
                }

                var nested = OpenListing(item, itemPath, out var whyNot);
                if (nested is null)
                {
                    if (whyNot is not null)
                    {
                        found.Add($"{itemPath}: what it holds cannot be listed by this account ({whyNot}), so who can change that is unknown");
                    }

                    continue;
                }

                using (nested)
                {
                    // The same object, opened again to list it: if its owner has made it a mount point since,
                    // what it lists is its own, empty, self -- but it is a link now, and said to be one.
                    if (FileObjects.Inspect(nested, itemPath).IsLink)
                    {
                        found.Add($"{itemPath} is a link, made one while this looked");
                        continue;
                    }

                    ContentExposures(nested, itemPath, trusted, found);
                }
            }
        }
    }

    /// <summary>
    /// The object <paramref name="item"/> has open, opened again to list what it holds; null, saying why in
    /// <paramref name="whyNot"/>, when this account may not, or another program's handle forbids it.
    /// </summary>
    /// <remarks>Null with no reason when it is being deleted.</remarks>
    private static SafeFileHandle? OpenListing(SafeFileHandle item, string path, out string? whyNot)
    {
        whyNot = null;
        try
        {
            return FileObjects.OpenChild(item, string.Empty, FileObjects.ListDirectory | FileObjects.ReadAttributes, Shared, path);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException || (ex is IOException && ex.HResult == SharingViolation))
        {
            whyNot = ex.Message;
            return null;
        }
    }

    /// <summary>
    /// Opens a directory on the way to <paramref name="full"/>, or <paramref name="full"/> itself, as itself,
    /// and reads its ACL through that handle; null when it does not exist.
    /// </summary>
    /// <param name="directory">The directory.</param>
    /// <param name="full">The directory being protected or judged, for messages.</param>
    /// <param name="access">The rights wanted besides <see cref="FileObjects.ReadControl"/>, which is always asked for.</param>
    /// <param name="aclOptional">Whether a directory this account may not read the ACL of is opened anyway, with a null ACL.</param>
    /// <param name="acl">Its owner and DACL, or null when unreadable.</param>
    /// <param name="share">What others may do with it meanwhile.</param>
    /// <exception cref="ConfigurationException">It is a link, or a file.</exception>
    private static SafeFileHandle? OpenOnTheWay(
        string directory, string full, uint access, bool aclOptional, out FileSystemSecurity? acl, FileShare share = Shared)
    {
        acl = null;
        var readable = true;
        SafeFileHandle? handle;
        try
        {
            handle = FileObjects.Open(directory, access | FileObjects.ReadControl, share);
        }
        catch (UnauthorizedAccessException) when (aclOptional)
        {
            readable = false;
            handle = FileObjects.Open(directory, access, share);
        }

        if (handle is null)
        {
            return null;
        }

        try
        {
            RequireDirectory(FileObjects.Inspect(handle, directory), directory, full);
            if (readable)
            {
                acl = FileObjects.ReadAcl(handle, isDirectory: true);
            }

            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static string FullPath(string path) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

    private static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

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
    /// already in it; refuses one that is, or is reached through, or holds, a link, and one below a
    /// directory someone else could rename.
    /// </summary>
    /// <remarks>
    /// <para>Refuses a drive root: <c>C:\</c> itself lets every user create folders, so it always reads as
    /// exposed, and protecting it would lock every user out of the whole drive. A server belongs in a
    /// directory of its own.</para>
    /// <para>Each directory from the root down is opened without following a link and checked, and the
    /// directory itself is held open, shared for reading only, until the work is done, and its ACL is
    /// written through that handle. A check by name alone would leave a moment in which whoever can still
    /// write it -- that is why it is being protected -- renames it and puts a junction in its place, and the
    /// ACL, and the takeover of its contents, would land on wherever that points: System32, say. Held this
    /// way, nobody can rename or delete it meanwhile.</para>
    /// <para>The directories above are judged rather than held: one someone else can rename, or whose
    /// parent lets them remove it, they could swap for their own at any time, before this or after it, and
    /// everything below would be theirs -- the artifact directory where <c>update_self</c> writes the
    /// script SYSTEM runs included. That is refused, before anything below it is created. Holding them
    /// open would not help, and needs the right to list each, which a NetworkService service has on its
    /// own directory but not on every directory above it.</para>
    /// <para>A directory that does not exist is created with the ACL already on it, not given it
    /// afterwards: in between it would inherit "Authenticated Users: Modify" from <c>C:\</c>, and a handle
    /// a user opened then keeps that access whatever the ACL later says. So is any directory above it that
    /// does not exist yet. Created only if nothing is there: one somebody made a moment before is theirs,
    /// and is judged as any directory already there would be, not taken for the one asked for.</para>
    /// <para>What is already inside is taken over: see <see cref="TakeOverContents"/>. The directory's own
    /// ACL is written so that it reaches nothing else -- see <see cref="FileObjects.WriteSecurity"/> -- and
    /// each item gets its own only once it has been judged. tools/windiag-acl.ps1 does none of this to a
    /// directory that already exists: without handles opened this way, which it cannot have before
    /// anything from this repository is on the target, it refuses one this would have to take over.</para>
    /// </remarks>
    /// <exception cref="ConfigurationException">A drive root, a file, a link, or a directory others could redirect.</exception>
    public static void ProtectDirectory(string path, SecurityIdentifier? serviceAccount, bool ownedByAdministrators)
    {
        var full = FullPath(path);
        if (Same(full, Path.TrimEndingDirectorySeparator(Path.GetPathRoot(full) ?? string.Empty)))
        {
            throw new ConfigurationException(
                $"{full} is the root of a drive, which every user can write to, and restricting it would lock "
                + "them out of the whole drive. Put WinDiag.Mcp.exe and its artifacts in directories of their "
                + @"own, such as C:\WinDiag and C:\WinDiagArtifacts.");
        }

        var above = TrustedAbove(serviceAccount);
        var acl = DirectoryAcl(serviceAccount, ownedByAdministrators);
        var descriptor = acl.GetSecurityDescriptorBinaryForm();
        var write = FileObjects.WriteDac | (ownedByAdministrators ? FileObjects.WriteOwner : 0);

        SafeFileHandle? held = null;
        try
        {
            var parentPath = Path.GetPathRoot(full)!;
            FileSystemSecurity? parent;
            using (OpenOnTheWay(parentPath, full, FileObjects.ReadAttributes, aclOptional: true, out parent))
            {
            }

            foreach (var component in Components(full))
            {
                if (parent is not null && Exposures(parent, RemoveChildRights, above, "remove what is in") is { Count: > 0 } removable)
                {
                    throw RedirectRefusal(parentPath, full, removable);
                }

                // The directory itself is held for listing and shared for reading only: share modes bind
                // only an open that asks for data access, and no-one may open it to write -- to set a
                // reparse point on it -- or to rename or delete it while this works.
                var hold = Same(component, full);
                var access = hold ? FileObjects.ListDirectory | FileObjects.ReadAttributes | FileObjects.Synchronize | write : FileObjects.ReadAttributes;
                var share = hold ? FileShare.Read : Shared;

                var made = false;
                var handle = OpenOnTheWay(component, full, access, aclOptional: !hold, out var own, share);
                if (handle is null)
                {
                    made = FileObjects.CreateDirectory(component, descriptor);
                    handle = OpenOnTheWay(component, full, access, aclOptional: !hold, out own, share)
                             ?? throw new DirectoryNotFoundException($"{component} was created and is gone again.");
                }

                if (hold)
                {
                    held = handle;
                    break;
                }

                handle.Dispose();
                if (!made && own is not null && Exposures(own, RenameRights, above, "rename or remove") is { Count: > 0 } renamable)
                {
                    throw RedirectRefusal(component, full, renamable);
                }

                parentPath = component;
                parent = own;
            }

            // Before anything is changed, so a directory holding a link is refused untouched. Judged again
            // item by item below, since until the directory is restricted its contents can still change.
            RefuseLinksWithin(held!, full);

            FileObjects.WriteSecurity(held!, descriptor, withOwner: ownedByAdministrators, protectedDacl: true, full);

            // Judged again before it is entered: an owner who could still write it a moment ago may have
            // made it a mount point, and the ACL written through the handle went on the mount point itself.
            RequireDirectory(FileObjects.Inspect(held!, full), full, full);
            TakeOverContents(held!, full, ItemDescriptor(acl, isDirectory: true), ItemDescriptor(acl, isDirectory: false), ownedByAdministrators);
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

    private static ConfigurationException RedirectRefusal(string directory, string full, IReadOnlyList<string> who) => new(
        $"{directory} can be renamed or removed, or what it holds removed, by accounts other than SYSTEM and "
        + $"Administrators ({string.Join("; ", who)}), and {full} is {(Same(directory, full) ? "it" : "below it")}: "
        + "they could put a directory of their own in its place, and the service would then run, or write, "
        + "whatever is there. Nothing below it was created or changed. " + RedirectRemedy(directory));

    /// <summary>What an operator does about a directory above windiag's that others can change; shared by both refusals.</summary>
    /// <remarks>
    /// Names the owner case on its own: a directory already restricted to administrators by hand still fails
    /// when its owner is an account outside the group, or one in it only through a domain group, and "restrict
    /// it" alone sent that operator round in circles.
    /// </remarks>
    internal static string RedirectRemedy(string directory) =>
        $"Remove the rights the accounts named hold on {directory}; if one of them owns it, hand it to the "
        + $"Administrators group (icacls \"{directory}\" /setowner *S-1-5-32-544) -- an account counts as an "
        + "administrator here only as a direct member of the local Administrators group. Or give windiag "
        + @"directories whose every parent only administrators can change, such as C:\WinDiag and C:\WinDiagArtifacts.";

    /// <summary>
    /// Hands each item the listed directory holds, at any depth, to Administrators, and replaces its ACL
    /// with what an item created there afresh would get.
    /// </summary>
    /// <remarks>
    /// <para>Protecting the directory replaces only what its contents inherit. Each item keeps its owner
    /// and its explicit ACEs, and an owner can always grant itself write access again -- so a
    /// <c>self-update.cmd</c> or a signed <c>handle64.exe</c> a user made while the directory was writable
    /// would stay theirs to rewrite, under SYSTEM's nose.</para>
    /// <para>The ACL written has no explicit ACE and inherits the directory's: SYSTEM, Administrators, and a
    /// service account's ACE when there is one, which must reach what the service runs and writes. Written
    /// whole, inherited ACEs included, because nothing computes them from the parent on this path -- and
    /// never empty of rules, which .NET's own security objects write as "Everyone: Full Control".</para>
    /// <para>Each item is opened by its bare name relative to the handle on the directory that listed it,
    /// without following a link, judged, and written through that handle; a directory is then opened again
    /// through it -- the same object, not its name -- judged again, and listed. Nothing is ever reached by a
    /// path that could have been made to lead elsewhere after it was judged. A directory is listed only
    /// after it is restricted, so nothing can be added to it between the listing and the reset.</para>
    /// <para>When <paramref name="ownedByAdministrators"/> is false -- a service account that cannot assign
    /// that owner -- owners are left, and the exposure check that follows names any that is not
    /// trusted.</para>
    /// </remarks>
    private static void TakeOverContents(
        SafeFileHandle listing, string path, byte[] directoryItem, byte[] fileItem, bool ownedByAdministrators)
    {
        var access = FileObjects.ReadControl | FileObjects.WriteDac | FileObjects.ReadAttributes
                     | (ownedByAdministrators ? FileObjects.WriteOwner : 0);

        foreach (var name in FileObjects.Children(listing, path))
        {
            var itemPath = Path.Join(path, name);
            SafeFileHandle? item;
            try
            {
                item = FileObjects.OpenChild(listing, name, access, Shared, itemPath);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new ConfigurationException(TakeOverRefusal(itemPath, ex.Message, ownedByAdministrators));
            }

            if (item is null)
            {
                // Gone since the listing: moved out by its owner. Nothing can take its place, since the
                // directory it was in is restricted now.
                continue;
            }

            using (item)
            {
                var node = FileObjects.Inspect(item, itemPath);
                RefuseToTakeOver(node, itemPath);
                FileObjects.WriteSecurity(item, node.IsDirectory ? directoryItem : fileItem, withOwner: ownedByAdministrators, protectedDacl: false, itemPath);
                if (!node.IsDirectory)
                {
                    continue;
                }

                var nested = OpenListing(item, itemPath, out var whyNot);
                if (nested is null)
                {
                    if (whyNot is null)
                    {
                        // Being deleted: its owner removed it after it was judged.
                        continue;
                    }

                    throw new ConfigurationException(
                        $"{itemPath} was taken over but what it holds cannot be listed ({whyNot}). If another "
                        + "program holds it open, restart the machine, which closes every handle, and run this again.");
                }

                using (nested)
                {
                    RefuseToTakeOver(FileObjects.Inspect(nested, itemPath), itemPath);
                    TakeOverContents(nested, itemPath, directoryItem, fileItem, ownedByAdministrators);
                }
            }
        }
    }

    /// <summary>Why an item could not be opened to be taken over, and what the operator does about it.</summary>
    /// <remarks>
    /// The same denial means two different things. To SYSTEM or an elevated installer, which may always
    /// change an ACL as an administrator, it means the item's ACL shuts out even administrators. To a
    /// NetworkService or LocalService service it is the ordinary state of any file an administrator
    /// deployed: the account may modify it but not change its ACL, which only its owner may -- and telling
    /// that operator to delete the item, perhaps WinDiag.Mcp.exe itself, blamed a hostile ACL that was not
    /// there.
    /// </remarks>
    internal static string TakeOverRefusal(string itemPath, string reason, bool ownedByAdministrators) => ownedByAdministrators
        ? $"{itemPath} cannot be taken over by this account ({reason}): its ACL shuts out even administrators, "
          + "which nothing windiag makes does. Take it over and remove it as an administrator "
          + $"(takeown /a /r /d y /f \"{itemPath}\", then delete it), and run this again."
        : $"{itemPath} cannot be taken over by this service's account ({reason}): a service that does not run as "
          + "SYSTEM may not change the ACL of an item it does not own, as anything an administrator put there is. "
          + "Re-run --install-service from an elevated prompt, which takes the directory over, or run the service as LocalSystem.";

    /// <summary>Refuses a link or hard link anywhere the listed directory holds, changing nothing.</summary>
    /// <remarks>
    /// Read-only and a courtesy: it lets the common case be refused untouched. The takeover judges each
    /// item again, through the handle it writes, and is what decides; an item this cannot open or list is
    /// left to it.
    /// </remarks>
    private static void RefuseLinksWithin(SafeFileHandle listing, string path)
    {
        foreach (var name in FileObjects.Children(listing, path))
        {
            var itemPath = Path.Join(path, name);
            SafeFileHandle? item;
            try
            {
                item = FileObjects.OpenChild(listing, name, FileObjects.ReadAttributes, Shared, itemPath);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            if (item is null)
            {
                continue;
            }

            using (item)
            {
                var node = FileObjects.Inspect(item, itemPath);
                RefuseToTakeOver(node, itemPath);
                if (!node.IsDirectory || OpenListing(item, itemPath, out _) is not { } nested)
                {
                    continue;
                }

                using (nested)
                {
                    RefuseToTakeOver(FileObjects.Inspect(nested, itemPath), itemPath);
                    RefuseLinksWithin(nested, itemPath);
                }
            }
        }
    }

    /// <summary>
    /// The security for an item in a directory given <paramref name="directory"/>: the same owner, and as
    /// its only ACEs, the directory's inheritable ones, marked inherited -- what an item created there would get.
    /// </summary>
    /// <remarks>
    /// Derived from the directory's own descriptor, so the two cannot drift apart. A file takes each
    /// object-inherit ACE as an effective one; a directory takes each container-inherit ACE with its
    /// inheritance flags, to pass on in turn, and an object-inherit-only one as inherit-only.
    /// </remarks>
    internal static byte[] ItemDescriptor(DirectorySecurity directory, bool isDirectory)
    {
        var parent = new RawSecurityDescriptor(directory.GetSecurityDescriptorBinaryForm(), 0);
        var dacl = new RawAcl(GenericAcl.AclRevision, parent.DiscretionaryAcl?.Count ?? 0);
        foreach (var ace in parent.DiscretionaryAcl?.OfType<CommonAce>() ?? [])
        {
            var inherits = ace.AceFlags;
            AceFlags flags;
            if (!isDirectory)
            {
                if (!inherits.HasFlag(AceFlags.ObjectInherit))
                {
                    continue;
                }

                flags = AceFlags.Inherited;
            }
            else if (inherits.HasFlag(AceFlags.ContainerInherit))
            {
                flags = AceFlags.Inherited | (inherits & (AceFlags.ContainerInherit | AceFlags.ObjectInherit));
            }
            else if (inherits.HasFlag(AceFlags.ObjectInherit))
            {
                flags = AceFlags.Inherited | AceFlags.ObjectInherit | AceFlags.InheritOnly;
            }
            else
            {
                continue;
            }

            dacl.InsertAce(dacl.Count, new CommonAce(flags, ace.AceQualifier, ace.AccessMask, ace.SecurityIdentifier, isCallback: false, opaque: null));
        }

        if (dacl.Count == 0)
        {
            // An empty DACL would shut everyone out but the owner; not what any directory this writes gives.
            throw new InvalidOperationException("The directory's ACL has nothing for its contents to inherit.");
        }

        var item = new RawSecurityDescriptor(
            ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclAutoInherited | ControlFlags.SelfRelative,
            parent.Owner, group: null, systemAcl: null, discretionaryAcl: dacl);
        var bytes = new byte[item.BinaryLength];
        item.GetBinaryForm(bytes, 0);
        return bytes;
    }

    /// <summary>Throws for an item the takeover must not touch.</summary>
    /// <remarks>
    /// <para>A junction or symbolic link points where its maker chose; in a directory others could write,
    /// that may be anywhere, and an administrator's junction retargeted. Its own ACL could be taken over
    /// safely, but what it leads to would stay theirs. Refused rather than skipped: a link nobody expected
    /// is itself the warning.</para>
    /// <para>A hard link is the same file as one elsewhere on the volume, and its ACL is that file's. A
    /// user can link any file they can read -- a System32 binary included -- and taking it over would hand
    /// it to Administrators and, through inheritance, to the service's account. Nothing windiag writes has
    /// a second name.</para>
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
                + "restrict that one too. It was left as it was, and so was that one. Windiag never makes one. "
                + "Remove it and run this again.");
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
