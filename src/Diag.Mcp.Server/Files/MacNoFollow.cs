using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Diag.Mcp.Server.Files;

/// <summary>macOS's own open(2) and errno values, from &lt;sys/fcntl.h&gt; and &lt;sys/errno.h&gt;.</summary>
/// <remarks>Apart from <see cref="MacNoFollow"/> so the values can be pinned by a test on every OS.</remarks>
internal static class MacOpenFlags
{
    public const int O_WRONLY = 0x1;
    public const int O_APPEND = 0x8;
    public const int O_NOFOLLOW = 0x100;
    public const int O_CLOEXEC = 0x1000000;
    public const int ELOOP = 62;
    public const int EINTR = 4;

    /// <summary>Every append's flags. Never O_CREAT, so open is called without its variadic mode argument.</summary>
    public const int Append = O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC;
}

/// <summary>Appending on macOS without following a link at the destination.</summary>
/// <remarks>
/// <para>The check-then-open fallback leaves a window in which a link swapped in is followed -- by a root
/// daemon. Here open(2) refuses the link itself (O_NOFOLLOW, ELOOP).</para>
/// <para>Not LinuxNoFollow with other numbers. The file is created by .NET's CreateNew, which fails on any
/// existing entry, a link included, and each append opens it with the two-argument open: no O_CREAT, so no
/// variadic mode argument, which Apple arm64 passes on the stack where a fixed declaration would put it in a
/// register. Bytes go out through write(2), never a FileStream, whose positioned writes macOS would honour
/// on an O_APPEND descriptor and so overwrite the start of the file.</para>
/// </remarks>
[SupportedOSPlatform("macos")]
internal static class MacNoFollow
{
    static MacNoFollow() => SystemLibrary.RegisterFor(typeof(MacNoFollow).Assembly);

    public static void Append(string path, ReadOnlySpan<byte> content)
    {
        // A dangling link is not "missing": File.Exists follows it and says false, so the link is checked too.
        if (!File.Exists(path) && new FileInfo(path).LinkTarget is null)
        {
            try
            {
                using var created = new FileStream(path, new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
                });
            }
            catch (IOException) when (File.Exists(path) || new FileInfo(path).LinkTarget is not null)
            {
                // Created by a racing chunk, or a link planted in the window: open below appends to the one
                // and refuses the other.
            }
        }

        var fd = open(path, MacOpenFlags.Append);
        if (fd < 0)
        {
            var errno = Marshal.GetLastPInvokeError();
            throw errno == MacOpenFlags.ELOOP
                ? new FileTransferException($"'{path}' is a symbolic link, so this chunk was not appended. Start the transfer over.")
                : new IOException(Marshal.GetPInvokeErrorMessage(errno), errno);
        }

        try
        {
            while (!content.IsEmpty)
            {
                var written = write(fd, ref MemoryMarshal.GetReference(content), content.Length);
                if (written < 0)
                {
                    var errno = Marshal.GetLastPInvokeError();
                    if (errno == MacOpenFlags.EINTR)
                    {
                        continue;
                    }

                    throw new IOException(Marshal.GetPInvokeErrorMessage(errno), errno);
                }

                content = content[(int)written..];
            }
        }
        finally
        {
            _ = close(fd);
        }
    }

    [DllImport(SystemLibrary.C, SetLastError = true)]
    private static extern int open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);

    [DllImport(SystemLibrary.C, SetLastError = true)]
    private static extern nint write(int fd, ref byte buffer, nint count);

    [DllImport(SystemLibrary.C, SetLastError = true)]
    private static extern int close(int fd);
}
