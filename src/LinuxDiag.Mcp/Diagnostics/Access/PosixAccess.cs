using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Diagnostics.Access;

/// <summary>The kernel's permission check, in the kernel's order, with the rule that decided in words.</summary>
/// <remarks>
/// Follows generic_permission and posix_acl_permission. Three rules surprise people and are the usual
/// answer to "why is this denied": the owner is judged by the owner bits alone; a group member by the
/// group class alone, never falling through to other; and a named ACL entry is cut down by the mask.
/// </remarks>
public static class PosixAccess
{
    public static (bool Allowed, string Reason) Check(AccessSubject who, FileFacts file, AccessRights want)
    {
        ArgumentNullException.ThrowIfNull(who);
        ArgumentNullException.ThrowIfNull(file);

        // do_faccessat: a device, FIFO or socket on a read-only mount is still writable.
        if (want.HasFlag(AccessRights.Write) && file.ReadOnlyMount && (file.IsRegular || file.IsDirectory))
        {
            return (false, "the filesystem is mounted read-only");
        }

        if (want.HasFlag(AccessRights.Write) && file.Immutable)
        {
            return (false, "the file is immutable (chattr +i): nobody, root included, can write it");
        }

        if (want.HasFlag(AccessRights.Execute) && file.IsRegular && file.NoExecMount)
        {
            return (false, "the filesystem is mounted noexec");
        }

        var (granted, reason) = Bits(who, file, want);
        if (granted)
        {
            return (true, reason);
        }

        // Capabilities are asked only after the bits refuse, as the kernel does.
        var someoneMayExecute = (file.Permissions & 0b001_001_001) != 0;
        if (who.DacOverride && (file.IsDirectory || !want.HasFlag(AccessRights.Execute) || someoneMayExecute))
        {
            return (true, $"CAP_DAC_OVERRIDE bypasses the bits, which alone refuse ({reason})");
        }

        var readSearch = file.IsDirectory ? AccessRights.Read | AccessRights.Execute : AccessRights.Read;
        if (who.DacReadSearch && (want & ~readSearch) == 0)
        {
            return (true, $"CAP_DAC_READ_SEARCH bypasses the bits, which alone refuse ({reason})");
        }

        return (false, reason);
    }

    private static (bool, string) Bits(AccessSubject who, FileFacts file, AccessRights want)
    {
        // An ACL's user:: entry is the owner bits, so the owner is decided the same way with or without one.
        if (who.UserId == file.Owner)
        {
            return Grant((file.Permissions >> 6) & 7, want, $"owner (uid {file.Owner})");
        }

        // acl_permission_check asks the ACL only when the group bits -- the mask -- are non-zero; with mask::---
        // every named entry is void and the other bits decide.
        if (file.Acl is { } acl && (file.Permissions & 0b000_111_000) != 0)
        {
            return Acl(who, file, acl, want);
        }

        return who.Groups.Contains(file.Group)
            ? Grant((file.Permissions >> 3) & 7, want, $"group class, through the owning group (gid {file.Group})")
            : Grant(file.Permissions & 7, want, "other class");
    }

    private static (bool, string) Acl(AccessSubject who, FileFacts file, IReadOnlyList<AclEntry> acl, AccessRights want)
    {
        var mask = acl.FirstOrDefault(e => e.Tag == AclTag.Mask)?.Permissions;
        int Masked(int permissions) => mask is { } m ? permissions & m : permissions;
        string MaskNote(int permissions) =>
            mask is { } m && (permissions & ~m) != 0 ? $", limited by mask::{PosixAcl.Rwx(m)} to {PosixAcl.Rwx(permissions & m)}" : string.Empty;
        bool Allows(int permissions) => ((int)want & ~permissions) == 0;

        if (acl.FirstOrDefault(e => e.Tag == AclTag.User && e.Id == who.UserId) is { } named)
        {
            return (Allows(Masked(named.Permissions)), $"named user entry user:{named.Id}:{PosixAcl.Rwx(named.Permissions)}{MaskNote(named.Permissions)}");
        }

        string Describe(AclEntry entry) => entry.Tag == AclTag.GroupObj
            ? $"group::{PosixAcl.Rwx(entry.Permissions)} (owning group, gid {file.Group})"
            : $"group:{entry.Id}:{PosixAcl.Rwx(entry.Permissions)}";

        var matching = acl.Where(e =>
            (e.Tag == AclTag.GroupObj && who.Groups.Contains(file.Group)) ||
            (e.Tag == AclTag.Group && e.Id is { } id && who.Groups.Contains(id))).ToList();
        if (matching.Count > 0)
        {
            // The first matching entry that grants the request decides, mask applied; none granting is a denial.
            if (matching.FirstOrDefault(e => Allows(e.Permissions)) is not { } granting)
            {
                return (false, $"group class: {string.Join(", ", matching.Select(Describe))} - none grants {PosixAcl.Rwx((int)want)}, and a matching group entry stops the check before other");
            }

            return (Allows(Masked(granting.Permissions)), $"group class, {Describe(granting)}{MaskNote(granting.Permissions)}");
        }

        return Grant(acl.FirstOrDefault(e => e.Tag == AclTag.Other)?.Permissions ?? (file.Permissions & 7), want, "other class");
    }

    private static (bool, string) Grant(int permissions, AccessRights want, string who) =>
        (((int)want & ~permissions) == 0, $"{who}: {PosixAcl.Rwx(permissions)}");
}
