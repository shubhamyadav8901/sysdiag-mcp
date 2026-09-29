using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Diag.Mcp.Server.Files;

/// <summary>Opening for append with O_NOFOLLOW, so a link at the path is refused by the kernel itself.</summary>
/// <remarks>
/// FileStream cannot pass O_NOFOLLOW, so the managed path is a check followed by an open, and a link
/// swapped in between the two is followed. On a root server holding the arbitrary-write grant that
/// window is real. The flag values here are x86-64 Linux's -- arm64 differs for O_NOFOLLOW -- so this is
/// used only where Supported is true, and anything else keeps the checked open.
/// </remarks>
[SupportedOSPlatform("linux")]
internal static class LinuxNoFollow
{
    private const int O_WRONLY = 0x1;
    private const int O_CREAT = 0x40;
    private const int O_APPEND = 0x400;
    private const int O_NOFOLLOW = 0x20000;
    private const int O_CLOEXEC = 0x80000;
    private const int ELOOP = 40;
    private const int OwnerReadWrite = 0b110_000_000; // 0600, applied only when the file is created

    public static bool Supported => RuntimeInformation.ProcessArchitecture == Architecture.X64;

    public static FileStream OpenForAppend(string path)
    {
        var fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, OwnerReadWrite);
        if (fd < 0)
        {
            var errno = Marshal.GetLastPInvokeError();
            if (errno == ELOOP)
            {
                throw new FileTransferException(
                    $"'{path}' is a symbolic link, so this chunk was not appended. Start the transfer over.");
            }

            throw new IOException(Marshal.GetPInvokeErrorMessage(errno), errno);
        }

        return new FileStream(new SafeFileHandle(fd, ownsHandle: true), FileAccess.Write);
    }

    // open(2) is variadic in C. On x86-64 a variadic int travels exactly as a fixed one does, which is
    // what makes this declaration sound there -- and another reason it is x86-64 only.
    [DllImport("libc", SetLastError = true)]
    private static extern int open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, int mode);
}
