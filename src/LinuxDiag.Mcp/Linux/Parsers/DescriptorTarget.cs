using System.Globalization;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <summary>What a <c>/proc/&lt;pid&gt;/fd/N</c> link points at, from its readlink text alone.</summary>
public static class DescriptorTarget
{
    public const string DeletedSuffix = " (deleted)";

    public static string Kind(string target)
    {
        ArgumentNullException.ThrowIfNull(target);

        if (target.StartsWith("socket:[", StringComparison.Ordinal)) return "Socket";
        if (target.StartsWith("pipe:[", StringComparison.Ordinal)) return "Pipe";
        if (target.StartsWith("anon_inode:", StringComparison.Ordinal)) return "AnonInode";
        if (target.StartsWith("/dev/", StringComparison.Ordinal)) return "Device";
        return target.StartsWith('/') ? "File" : "Other";
    }

    public static long? SocketInode(string target) => Bracketed(target, "socket:[");

    public static long? PipeInode(string target) => Bracketed(target, "pipe:[");

    public static bool IsDeleted(string target) => target.EndsWith(DeletedSuffix, StringComparison.Ordinal);

    private static long? Bracketed(string target, string prefix) =>
        target.StartsWith(prefix, StringComparison.Ordinal) && target.EndsWith(']') &&
        long.TryParse(target.AsSpan(prefix.Length, target.Length - prefix.Length - 1),
            NumberStyles.None, CultureInfo.InvariantCulture, out var inode)
            ? inode
            : null;
}
