using System.Buffers.Binary;

namespace LinuxDiag.Mcp.Linux.Parsers;

public enum AclTag
{
    UserObj = 0x01,
    User = 0x02,
    GroupObj = 0x04,
    Group = 0x08,
    Mask = 0x10,
    Other = 0x20,
}

/// <param name="Id">The uid or gid a named entry is for; null for the owner, owning group, mask and other.</param>
/// <param name="Permissions">rwx as 4, 2, 1.</param>
public sealed record AclEntry(AclTag Tag, uint? Id, int Permissions);

/// <summary>A POSIX ACL in the kernel's xattr form, as <c>system.posix_acl_access</c> holds it.</summary>
/// <remarks>Read from the xattr, not from getfacl: neither WSL distro installs the acl package, and a minimal host rarely does.</remarks>
public static class PosixAcl
{
    public const string AccessAttribute = "system.posix_acl_access";
    public const string DefaultAttribute = "system.posix_acl_default";

    private const uint Version = 2;
    private const uint UndefinedId = uint.MaxValue;

    public static IReadOnlyList<AclEntry> Parse(ReadOnlySpan<byte> blob)
    {
        if (blob.Length < 4 || (blob.Length - 4) % 8 != 0 || BinaryPrimitives.ReadUInt32LittleEndian(blob) != Version)
        {
            throw new FormatException("Not a version-2 POSIX ACL.");
        }

        var entries = new List<AclEntry>();
        for (var at = 4; at < blob.Length; at += 8)
        {
            var tag = (AclTag)BinaryPrimitives.ReadUInt16LittleEndian(blob[at..]);
            if (!Enum.IsDefined(tag))
            {
                throw new FormatException($"Unknown ACL tag 0x{(int)tag:x}.");
            }

            var id = BinaryPrimitives.ReadUInt32LittleEndian(blob[(at + 4)..]);
            entries.Add(new AclEntry(tag, id == UndefinedId ? null : id, BinaryPrimitives.ReadUInt16LittleEndian(blob[(at + 2)..]) & 7));
        }

        return entries;
    }

    /// <summary>getfacl's notation, with names where the account database has them and the mask's effect shown.</summary>
    public static IReadOnlyList<string> Describe(IReadOnlyList<AclEntry> acl, Func<uint, string?> userName, Func<uint, string?> groupName)
    {
        ArgumentNullException.ThrowIfNull(acl);

        var mask = acl.FirstOrDefault(e => e.Tag == AclTag.Mask)?.Permissions;
        return acl.Select(entry =>
        {
            var text = entry.Tag switch
            {
                AclTag.UserObj => $"user::{Rwx(entry.Permissions)}",
                AclTag.User => $"user:{Name(entry.Id, userName)}:{Rwx(entry.Permissions)}",
                AclTag.GroupObj => $"group::{Rwx(entry.Permissions)}",
                AclTag.Group => $"group:{Name(entry.Id, groupName)}:{Rwx(entry.Permissions)}",
                AclTag.Mask => $"mask::{Rwx(entry.Permissions)}",
                _ => $"other::{Rwx(entry.Permissions)}",
            };
            var masked = entry.Tag is AclTag.User or AclTag.GroupObj or AclTag.Group && mask is { } m && (entry.Permissions & ~m) != 0;
            return masked ? $"{text}  #effective:{Rwx(entry.Permissions & mask!.Value)}" : text;
        }).ToList();
    }

    public static string Rwx(int permissions) =>
        $"{((permissions & 4) != 0 ? 'r' : '-')}{((permissions & 2) != 0 ? 'w' : '-')}{((permissions & 1) != 0 ? 'x' : '-')}";

    private static string Name(uint? id, Func<uint, string?> lookUp) =>
        id is { } value ? lookUp(value) ?? value.ToString(System.Globalization.CultureInfo.InvariantCulture) : "?";
}
