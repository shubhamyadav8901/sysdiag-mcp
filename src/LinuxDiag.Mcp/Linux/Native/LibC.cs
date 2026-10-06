using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Diag.Mcp.Server.Files;
using Microsoft.Win32.SafeHandles;

namespace LinuxDiag.Mcp.Linux.Native;

/// <param name="Mode">st_mode: the file type and permission bits.</param>
public readonly record struct FileIdentity(uint DeviceMajor, uint DeviceMinor, ulong Inode, ushort Mode)
{
    public bool IsFifo => (Mode & 0xF000) == 0x1000;

    public bool IsDirectory => (Mode & 0xF000) == 0x4000;

    public bool IsRegular => (Mode & 0xF000) == 0x8000;
}

/// <param name="Mode">st_mode: file type, permission bits, and setuid/setgid/sticky.</param>
/// <param name="Immutable">chattr +i: nobody, root included, may write, rename or delete it.</param>
/// <param name="AppendOnly">chattr +a: writes may only append.</param>
public readonly record struct FileStatus(uint UserId, uint GroupId, ushort Mode, bool Immutable, bool AppendOnly)
{
    public bool IsDirectory => (Mode & 0xF000) == 0x4000;

    public bool IsRegular => (Mode & 0xF000) == 0x8000;
}

public sealed record AccountEntry(string Name, uint UserId, uint GroupId, string Home);

/// <summary>A path that leads to a FIFO, device or socket, which a reader of files must never open.</summary>
public sealed class NotRegularFileException : IOException, IDiagnosticException
{
    public NotRegularFileException(string path)
        : base($"'{path}' is not a regular file (a FIFO, device or socket), so it was not opened.")
    {
    }
}

/// <summary>A C-library call's failure, with its errno for a caller that maps it to words.</summary>
public sealed class ErrnoException : Exception, IDiagnosticException
{
    public const int EPERM = 1;
    public const int ENOENT = 2;
    public const int ESRCH = 3;
    public const int EINVAL = 22;
    public const int ENOSYS = 38;

    public ErrnoException(string operation, int errno)
        : base($"{operation} failed: {Marshal.GetPInvokeErrorMessage(errno)}") => Errno = errno;

    public int Errno { get; }
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
    private const int EBADF = 9;
    private const int ETXTBSY = 26;
    private const int EROFS = 30;
    private const int ERANGE = 34;
    private const int ENODATA = 61;
    private const int ENOTSUP = 95;
    private const int AtEaccess = 0x200;
    private const ulong StatxAttrImmutable = 0x10;
    private const ulong StatxAttrAppend = 0x20;
    private const int PasswdSize = 48;
    private const int ORdOnly = 0;
    private const int ONoCtty = 0x100;
    private const int ONonBlock = 0x800;
    private const int OCloExec = 0x80000;
    private const int OPath = 0x200000;
    private const int AtEmptyPath = 0x1000;
    private const int GroupSize = 32;

    public const int ROk = 4;
    public const int WOk = 2;
    public const int XOk = 1;

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

    /// <summary>statx into the buffer: false when nothing is at the path, a throw for anything else.</summary>
    private static bool Statx(string path, Span<byte> buffer)
    {
        if (statx(AtFdCwd, path, AtStatxDontSync, StatxBasicStats, ref MemoryMarshal.GetReference(buffer)) == 0)
        {
            return true;
        }

        var errno = Marshal.GetLastPInvokeError();
        return errno switch
        {
            ENOENT or ESRCH or ENOTDIR => false,
            EACCES or EPERM => throw new UnauthorizedAccessException($"Permission denied reading '{path}'."),
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
        if (!Statx(path, buffer))
        {
            return null;
        }

        return new FileIdentity(
            BinaryPrimitives.ReadUInt32LittleEndian(buffer[136..]),
            BinaryPrimitives.ReadUInt32LittleEndian(buffer[140..]),
            BinaryPrimitives.ReadUInt64LittleEndian(buffer[32..]),
            BinaryPrimitives.ReadUInt16LittleEndian(buffer[28..]));
    }

    /// <summary>Owner, group, mode and the immutable and append-only attributes, links followed; null when nothing is there.</summary>
    public static FileStatus? Status(string path)
    {
        Span<byte> buffer = stackalloc byte[256];
        if (!Statx(path, buffer))
        {
            return null;
        }

        // stx_attributes at 8, masked by stx_attributes_mask at 56: a filesystem that cannot report an attribute leaves its bit clear.
        var attributes = BinaryPrimitives.ReadUInt64LittleEndian(buffer[8..]) & BinaryPrimitives.ReadUInt64LittleEndian(buffer[56..]);
        return new FileStatus(
            BinaryPrimitives.ReadUInt32LittleEndian(buffer[20..]),
            BinaryPrimitives.ReadUInt32LittleEndian(buffer[24..]),
            BinaryPrimitives.ReadUInt16LittleEndian(buffer[28..]),
            (attributes & StatxAttrImmutable) != 0,
            (attributes & StatxAttrAppend) != 0);
    }

    /// <summary>A read handle on a regular file; a FIFO, device or socket throws <see cref="NotRegularFileException"/>.</summary>
    /// <remarks>
    /// <para>For every file whose path comes from configuration another account controls: a user's unit link,
    /// a crontab command, a program an autostart entry names. Opening a FIFO blocks until a writer comes;
    /// /dev/zero never ends; opening /dev/watchdog arms it and reboots the machine when nobody pets it.</para>
    /// <para>The path is taken with O_PATH, which opens nothing, and its type is read from that descriptor. Only a
    /// regular file is reopened for reading, through /proc/self/fd, so the file read is the file checked --
    /// swapping the path for a FIFO in between changes nothing.</para>
    /// </remarks>
    public static SafeFileHandle OpenRegularFile(string path)
    {
        var located = open(path, OPath | OCloExec);
        if (located < 0)
        {
            throw OpenError(path, Marshal.GetLastPInvokeError());
        }

        using var locator = new SafeFileHandle(located, ownsHandle: true);
        Span<byte> buffer = stackalloc byte[256];
        if (statx(located, string.Empty, AtEmptyPath | AtStatxDontSync, StatxBasicStats, ref MemoryMarshal.GetReference(buffer)) != 0)
        {
            throw OpenError(path, Marshal.GetLastPInvokeError());
        }

        if ((BinaryPrimitives.ReadUInt16LittleEndian(buffer[28..]) & 0xF000) != 0x8000)
        {
            throw new NotRegularFileException(path);
        }

        var reopened = open($"/proc/self/fd/{located}", ORdOnly | ONonBlock | ONoCtty | OCloExec);
        return reopened < 0
            ? throw OpenError(path, Marshal.GetLastPInvokeError())
            : new SafeFileHandle(reopened, ownsHandle: true);
    }

    private static Exception OpenError(string path, int errno) => errno switch
    {
        ENOENT or ENOTDIR => new FileNotFoundException($"'{path}' does not exist.", path),
        EACCES or EPERM => new UnauthorizedAccessException($"Permission denied opening '{path}'."),
        _ => new IOException($"Could not open '{path}': {Marshal.GetPInvokeErrorMessage(errno)}", errno),
    };

    // open(2) is variadic in C; with no mode argument the two fixed parameters travel as in any call on x86-64.
    [DllImport(SystemLibrary.C, SetLastError = true)]
    private static extern int open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);

    /// <summary>An extended attribute's value, or null when the file has none by that name or the filesystem has no xattrs.</summary>
    public static byte[]? GetXattr(string path, string name)
    {
        // The value can grow between the size query and the read; ERANGE then means ask again.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var size = getxattr(path, name, null, 0);
            if (size < 0)
            {
                return NoXattr(path, Marshal.GetLastPInvokeError());
            }

            var value = new byte[size];
            var read = getxattr(path, name, value, size);
            if (read >= 0)
            {
                return value[..(int)read];
            }

            var errno = Marshal.GetLastPInvokeError();
            if (errno != ERANGE)
            {
                return NoXattr(path, errno);
            }
        }

        throw new IOException($"The extended attribute {name} on '{path}' kept changing size.");
    }

    /// <summary>The kernel's own answer for this process's effective credentials: LSMs, mounts and attributes included.</summary>
    /// <remarks>faccessat, never an open: opening a FIFO blocks, and opening a watchdog device arms it.</remarks>
    public static bool Access(string path, int mode)
    {
        if (faccessat(AtFdCwd, path, mode, AtEaccess) == 0)
        {
            return true;
        }

        var errno = Marshal.GetLastPInvokeError();
        return errno switch
        {
            EACCES or EPERM or EROFS or ETXTBSY => false,
            _ => throw new IOException(Marshal.GetPInvokeErrorMessage(errno), errno),
        };
    }

    public static AccountEntry? UserByName(string name) =>
        LookUp(PasswdSize, (record, buffer, size) =>
        {
            var error = getpwnam_r(name, record, buffer, size, out var result);
            return (error, result);
        }, ReadPasswd);

    public static AccountEntry? UserById(uint uid) =>
        LookUp(PasswdSize, (record, buffer, size) =>
        {
            var error = getpwuid_r(uid, record, buffer, size, out var result);
            return (error, result);
        }, ReadPasswd);

    public static string? GroupName(uint gid) =>
        LookUp(GroupSize, (record, buffer, size) =>
        {
            var error = getgrgid_r(gid, record, buffer, size, out var result);
            return (error, result);
        }, record => Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(record, 0)) ?? string.Empty);

    /// <summary>Every group the account belongs to, its primary group included, as the account database says.</summary>
    public static IReadOnlyList<uint> GroupsOf(string user, uint primaryGroup)
    {
        for (var capacity = 64; ; )
        {
            var groups = new uint[capacity];
            var count = capacity;
            if (getgrouplist(user, primaryGroup, groups, ref count) >= 0)
            {
                return groups[..count];
            }

            if (count <= capacity)
            {
                throw new IOException($"getgrouplist failed for '{user}'.");
            }

            capacity = count;
        }
    }

    /// <summary>A reentrant account lookup, the buffer grown until the record fits.</summary>
    /// <remarks>The _r forms: getpwnam's static record is overwritten by any other thread's lookup.</remarks>
    private static T? LookUp<T>(int recordSize, Func<nint, nint, nint, (int Error, nint Result)> call, Func<nint, T> read)
        where T : class
    {
        for (var size = 1024; ; size *= 4)
        {
            var record = Marshal.AllocHGlobal(recordSize);
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var (error, result) = call(record, buffer, size);
                if (result != 0)
                {
                    return read(record);
                }

                // Not found is a null result -- reported by some NSS modules as one of these errors instead.
                if (error is 0 or ENOENT or ESRCH or EBADF or EPERM)
                {
                    return null;
                }

                if (error != ERANGE || size >= 1 << 20)
                {
                    throw new ErrnoException("account lookup", error);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
                Marshal.FreeHGlobal(record);
            }
        }
    }

    // struct passwd on x86-64: name 0, passwd 8, uid 16, gid 20, gecos 24, dir 32, shell 40.
    private static AccountEntry ReadPasswd(nint record) => new(
        Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(record, 0)) ?? string.Empty,
        unchecked((uint)Marshal.ReadInt32(record, 16)),
        unchecked((uint)Marshal.ReadInt32(record, 20)),
        Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(record, 32)) ?? "/");

    private static byte[]? NoXattr(string path, int errno) => errno switch
    {
        ENODATA or ENOTSUP => null,
        EACCES or EPERM => throw new UnauthorizedAccessException($"Permission denied reading the attributes of '{path}'."),
        _ => throw new IOException(Marshal.GetPInvokeErrorMessage(errno), errno),
    };

    [DllImport(SystemLibrary.C, SetLastError = true)]
    private static extern nint getxattr(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, byte[]? value, nint size);

    [DllImport(SystemLibrary.C, SetLastError = true)]
    private static extern int faccessat(int dirfd, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int mode, int flags);

    [DllImport(SystemLibrary.C)]
    private static extern int getpwnam_r([MarshalAs(UnmanagedType.LPUTF8Str)] string name, nint record, nint buffer, nint size, out nint result);

    [DllImport(SystemLibrary.C)]
    private static extern int getpwuid_r(uint uid, nint record, nint buffer, nint size, out nint result);

    [DllImport(SystemLibrary.C)]
    private static extern int getgrgid_r(uint gid, nint record, nint buffer, nint size, out nint result);

    [DllImport(SystemLibrary.C)]
    private static extern int getgrouplist([MarshalAs(UnmanagedType.LPUTF8Str)] string user, uint group, uint[] groups, ref int count);

    /// <summary>The path with every link resolved, or null when some part of it does not exist.</summary>
    public static string? RealPath(string path)
    {
        var buffer = new byte[PathMax];
        if (realpath(path, buffer) != 0)
        {
            return Encoding.UTF8.GetString(buffer, 0, Array.IndexOf(buffer, (byte)0));
        }

        var errno = Marshal.GetLastPInvokeError();
        return errno switch
        {
            ENOENT or ENOTDIR => null,
            EACCES or EPERM => throw new UnauthorizedAccessException($"Permission denied resolving '{path}'."),
            _ => throw new IOException(Marshal.GetPInvokeErrorMessage(errno), errno),
        };
    }

    /// <summary>Gives the path itself -- never what a link there leads to -- to this owner and group.</summary>
    public static void ChangeOwner(string path, uint userId, uint groupId)
    {
        if (lchown(path, userId, groupId) != 0)
        {
            var errno = Marshal.GetLastPInvokeError();
            throw new IOException($"Could not change the owner of '{path}': {Marshal.GetPInvokeErrorMessage(errno)}", errno);
        }
    }

    /// <summary>The account this process acts as.</summary>
    public static uint EffectiveUserId() => geteuid();

    [DllImport(SystemLibrary.C, SetLastError = true)]
    private static extern int lchown([MarshalAs(UnmanagedType.LPUTF8Str)] string path, uint owner, uint group);

    [DllImport(SystemLibrary.C)]
    private static extern uint geteuid();

    [DllImport(SystemLibrary.C, SetLastError = true)]
    private static extern nint realpath([MarshalAs(UnmanagedType.LPUTF8Str)] string path, byte[] resolved);

    [DllImport(SystemLibrary.C, SetLastError = true)]
    private static extern int statx(
        int dirfd, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, ref byte buffer);

    [DllImport(SystemLibrary.C, SetLastError = true)]
    private static extern nint readlink([MarshalAs(UnmanagedType.LPUTF8Str)] string path, byte[] buffer, nint size);

    public const int SIGKILL = 9;
    public const int SIGTERM = 15;
    public const int SIGCONT = 18;
    public const int SIGSTOP = 19;

    private const long SysPidfdSendSignal = 424;
    private const long SysPidfdOpen = 434;
    private const short PollIn = 1;
    private const int EINTR = 4;

    /// <summary>A pidfd for the process: once open, a signal through it reaches that process or fails -- never a newcomer on its PID.</summary>
    public static SafeFileHandle OpenPidFd(int pid)
    {
        var fd = syscall(SysPidfdOpen, pid, 0, 0, 0);
        return fd < 0
            ? throw new ErrnoException("pidfd_open", Marshal.GetLastPInvokeError())
            : new SafeFileHandle((IntPtr)fd, ownsHandle: true);
    }

    public static void SendSignal(SafeFileHandle pidfd, int signal)
    {
        if (syscall(SysPidfdSendSignal, (long)pidfd.DangerousGetHandle(), signal, 0, 0) < 0)
        {
            throw new ErrnoException("pidfd_send_signal", Marshal.GetLastPInvokeError());
        }
    }

    /// <summary>Whether the process exits within the timeout: a pidfd becomes readable when it does.</summary>
    /// <remarks>
    /// Asked of the pidfd, not of /proc: a zombie keeps /proc/&lt;pid&gt; until its parent reaps it, so "the
    /// directory is still there" reports an exited process as running. Polled in slices so cancellation
    /// interrupts the wait.
    /// </remarks>
    public static bool WaitForExit(SafeFileHandle pidfd, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var left = timeout - watch.Elapsed;
            var request = new PollFd { Fd = (int)pidfd.DangerousGetHandle(), Events = PollIn };
            var ready = poll(ref request, 1, (int)Math.Clamp(left.TotalMilliseconds, 0, 250));
            if (ready > 0)
            {
                return true;
            }

            if (ready < 0 && Marshal.GetLastPInvokeError() is var errno && errno != EINTR)
            {
                throw new ErrnoException("poll", errno);
            }

            if (left <= TimeSpan.Zero)
            {
                return false;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PollFd
    {
        public int Fd;
        public short Events;
        public short Revents;
    }

    // syscall(2) is variadic in C. On x86-64 a variadic long travels exactly as a fixed one does, the same
    // reason the kit's open(2) declaration is sound there -- and another reason this class is x86-64 only.
    [DllImport(SystemLibrary.C, SetLastError = true)]
    private static extern long syscall(long number, long a1, long a2, long a3, long a4);

    [DllImport(SystemLibrary.C, SetLastError = true)]
    private static extern int poll(ref PollFd fds, ulong nfds, int timeout);
}
