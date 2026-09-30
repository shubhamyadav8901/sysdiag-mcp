using System.Runtime.InteropServices;
using System.Text;
using Diag.Mcp.Server.Files;

namespace LinuxDiag.Mcp.Linux.Native;

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

    [DllImport(SystemLibrary.C, SetLastError = true)]
    private static extern nint readlink([MarshalAs(UnmanagedType.LPUTF8Str)] string path, byte[] buffer, nint size);
}
