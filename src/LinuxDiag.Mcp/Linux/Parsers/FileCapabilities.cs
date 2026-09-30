using System.Buffers.Binary;
using System.Globalization;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <param name="Effective">Raised on exec rather than merely permitted.</param>
/// <param name="RootId">A v3 (namespaced) capability's owner: the root of the user namespace it applies in.</param>
public sealed record FileCapabilitySet(IReadOnlyList<string> Permitted, IReadOnlyList<string> Inheritable, bool Effective, uint? RootId);

/// <summary>A file's <c>security.capability</c> xattr: what executing it grants.</summary>
public static class FileCapabilities
{
    public const string Attribute = "security.capability";

    private static readonly string[] Names =
    [
        "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid", "setpcap",
        "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
        "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
        "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write", "audit_control", "setfcap",
        "mac_override", "mac_admin", "syslog", "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf",
        "checkpoint_restore",
    ];

    public static FileCapabilitySet Parse(ReadOnlySpan<byte> blob)
    {
        if (blob.Length < 4)
        {
            throw new FormatException("A capability xattr is at least 4 bytes.");
        }

        var magic = BinaryPrimitives.ReadUInt32LittleEndian(blob);
        var (words, size) = (magic & 0xFF000000) switch
        {
            0x01000000 => (1, 12),
            0x02000000 => (2, 20),
            0x03000000 => (2, 24),
            _ => throw new FormatException($"Unknown capability revision 0x{magic >> 24:x}."),
        };
        if (blob.Length < size)
        {
            throw new FormatException("The capability xattr is shorter than its revision requires.");
        }

        ulong permitted = 0, inheritable = 0;
        for (var i = 0; i < words; i++)
        {
            permitted |= (ulong)BinaryPrimitives.ReadUInt32LittleEndian(blob[(4 + (8 * i))..]) << (32 * i);
            inheritable |= (ulong)BinaryPrimitives.ReadUInt32LittleEndian(blob[(8 + (8 * i))..]) << (32 * i);
        }

        return new FileCapabilitySet(
            Named(permitted), Named(inheritable), (magic & 1) != 0,
            size == 24 ? BinaryPrimitives.ReadUInt32LittleEndian(blob[20..]) : null);
    }

    /// <summary>getcap's notation: <c>cap_net_raw=ep</c>.</summary>
    public static string Describe(FileCapabilitySet set)
    {
        ArgumentNullException.ThrowIfNull(set);

        var parts = new List<string>();
        if (set.Permitted.Count > 0)
        {
            parts.Add($"{string.Join(',', set.Permitted)}={(set.Effective ? "e" : "")}p");
        }

        if (set.Inheritable.Count > 0)
        {
            parts.Add($"{string.Join(',', set.Inheritable)}=i");
        }

        if (set.RootId is { } root)
        {
            parts.Add($"[rootid={root.ToString(CultureInfo.InvariantCulture)}]");
        }

        return string.Join(' ', parts);
    }

    private static List<string> Named(ulong bits) =>
        Enumerable.Range(0, 64).Where(i => (bits & (1UL << i)) != 0)
            .Select(i => i < Names.Length ? $"cap_{Names[i]}" : $"cap_{i.ToString(CultureInfo.InvariantCulture)}")
            .ToList();
}
