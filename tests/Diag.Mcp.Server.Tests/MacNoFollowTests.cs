using System.Runtime.Versioning;
using Diag.Mcp.Server.Files;

namespace Diag.Mcp.Server.Tests;

public sealed class MacNoFollowTests : IDisposable
{
    private readonly string _root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"mnf-{Guid.NewGuid():N}")).FullName;

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public void The_flags_are_macoss_own_values_from_sys_fcntl_h_and_sys_errno_h()
    {
        // <sys/fcntl.h>: O_WRONLY 0x1, O_APPEND 0x8, O_NOFOLLOW 0x100, O_CLOEXEC 0x1000000. <sys/errno.h>: ELOOP 62,
        // EINTR 4. Linux's O_APPEND (0x400) is macOS's O_TRUNC: a Linux value here would empty the file on every chunk.
        Assert.Equal(0x1 | 0x8 | 0x100 | 0x1000000, MacOpenFlags.Append);
        Assert.Equal(62, MacOpenFlags.ELOOP);
        Assert.Equal(4, MacOpenFlags.EINTR);
        Assert.Equal(0, MacOpenFlags.Append & 0x200); // never O_CREAT: open's variadic mode would travel wrongly on Apple arm64
    }

    [MacFact]
    [SupportedOSPlatform("macos")]
    public void An_append_creates_a_missing_file_owner_only_and_appends_to_an_existing_one()
    {
        var path = Path.Combine(_root, "part");

        MacNoFollow.Append(path, [1, 2]);
        MacNoFollow.Append(path, [3]);

        Assert.Equal([1, 2, 3], File.ReadAllBytes(path));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
    }

    [MacFact]
    [SupportedOSPlatform("macos")]
    public void A_link_at_the_destination_is_refused_by_open_itself()
    {
        var target = Path.Combine(_root, "target");
        File.WriteAllBytes(target, [9]);
        var link = Path.Combine(_root, "link");
        File.CreateSymbolicLink(link, target);

        Assert.Throws<FileTransferException>(() => MacNoFollow.Append(link, [1]));
        Assert.Equal([9], File.ReadAllBytes(target));
    }

    [MacFact]
    [SupportedOSPlatform("macos")]
    public void A_dangling_link_at_the_destination_is_refused_and_nothing_is_created_at_its_target()
    {
        var target = Path.Combine(_root, "absent");
        var link = Path.Combine(_root, "dangling");
        File.CreateSymbolicLink(link, target);

        Assert.Throws<FileTransferException>(() => MacNoFollow.Append(link, [1]));
        Assert.False(File.Exists(target));
    }
}
