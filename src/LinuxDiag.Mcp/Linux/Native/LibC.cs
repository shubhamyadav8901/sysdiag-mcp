using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using Diag.Mcp.Server.Files;

namespace LinuxDiag.Mcp.Linux.Native;

/// <param name="Mode">st_mode: the file type and permission bits.</param>
public readonly record struct FileIdentity(uint DeviceMajor, uint DeviceMinor, ulong Inode, ushort Mode)
{
    public bool IsFifo => (Mode & 0xF000) == 0x1000;

    public bool IsDirectory => (Mode & 0xF000) == 0x4000;
}

/// <summary>Every C-library call this server makes.</summary>
/// <remarks>
/// One class, because an assembly takes exactly one DllImport resolver and a second registration throws.
/// NativeImportGuard checks that every import here goes through the kit's system-name resolver.
/// </remarks>
internal static class LibC
{
    private const int ENOENT = 2;
    private const int ESRCH = 3;
    private const int EACCES = 13;
    private const int EPERM = 1;
    private const int PathMax = 4096;
    private const int ENOTDIR = 20;
    private const int AtFdCwd = -100;
    private const uint StatxBasicStats = 0x7ff;

    // AT_STATX_DONT_SYNC: answer from cached attributes. A sync would block without limit on a hard-mounted
    // NFS file whose server has gone, or a hung FUSE daemon -- and update_self waits for every in-flight call.
    private const int AtStatxDontSync = 0x4000;

    // Before the first call binds, so libc is never looked for beside the server.
    static LibC() => SystemLibrary.RegisterFor(typeof(LibC).Assembly);

    public static bool Supported => RuntimeInformation.ProcessArchitecture == Architecture.X64;

    /// <summary>A link's raw target, or null when there is nothing at the path; permission denied throws.</summary>
    /// <remarks>
    /// Not FileInfo.LinkTarget: that swallows every readlink error and returns null, so "another user's
    /// process, denied" and "not a link" read the same -- which is how a non-root answer came to look
    /// complete. Here EACCES is an UnauthorizedAccessException a caller can count.
    /// </remarks>
    public static string? ReadLink(string path)
    {
        var buffer = new byte[PathMax];
        var length = readlink(path, buffer, buffer.Length);
        if (length >= 0)
        {
            return Encoding.UTF8.GetString(buffer, 0, (int)length);
        }

        var errno = Marshal.GetLastPInvokeError();
        return errno switch
        {
            ENOENT or ESRCH => null,
            EACCES or EPERM => throw new UnauthorizedAccessException($"Permission denied reading the link '{path}'."),
            _ => throw new IOException(Marshal.GetPInvokeErrorMessage(errno), errno),
        };
    }

    /// <summary>The device and inode a path resolves to, links followed, or null when nothing is there.</summary>
    /// <remarks>
    /// <para>statx rather than stat: its struct is the kernel's own, identical on every architecture, so the
    /// offsets below are ABI rather than x86-64 layout. glibc has had the wrapper since 2.28.</para>
    /// <para>Given <c>/proc/&lt;pid&gt;/fd/N</c> it answers for the open file, whatever its name now -- which is
    /// how a holder is found even after the file was renamed, or through a container's own paths.</para>
    /// </remarks>
    public static FileIdentity? Identify(string path)
    {
        Span<byte> buffer = stackalloc byte[256];
        if (statx(AtFdCwd, path, AtStatxDontSync, StatxBasicStats, ref MemoryMarshal.GetReference(buffer)) != 0)
        {
            var errno = Marshal.GetLastPInvokeError();
            return errno switch
            {
                ENOENT or ESRCH or ENOTDIR => null,
                EACCES or EPERM => throw new UnauthorizedAccessException($"Permission denied reading '{path}'."),
                _ => throw new IOException(Marshal.GetPInvokeErrorMessage(errno), errno),
            };
        }

        return new FileIdentity(
            BinaryPrimitives.ReadUInt32LittleEndian(buffer[136..]),
            BinaryPrimitives.ReadUInt32LittleEndian(buffer[140..]),
            BinaryPrimitives.ReadUInt64LittleEndian(buffer[32..]),
            BinaryPrimitives.ReadUInt16LittleEndian(buffer[28..]));
    }

    [DllImport(SystemLibrary.C, SetLastError = true)]
    private static extern int statx(
        int dirfd, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, ref byte buffer);

    [DllImport(SystemLibrary.C, SetLastError = true)]
    private static extern nint readlink([MarshalAs(UnmanagedType.LPUTF8Str)] string path, byte[] buffer, nint size);
}
