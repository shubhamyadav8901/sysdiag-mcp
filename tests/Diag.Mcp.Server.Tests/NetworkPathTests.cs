using System.Diagnostics;
using Diag.Mcp.Server.Files;
using Microsoft.Extensions.Logging.Abstractions;

namespace Diag.Mcp.Server.Tests;

/// <summary>Which Windows spellings make the server connect out, or open a device, instead of a local file.</summary>
/// <remarks>
/// A path-taking tool given <c>\\attacker\x\y</c> opens an SMB connection, and a server running as
/// LocalSystem authenticates with the machine account's credentials: the classic coerced-authentication
/// primitive, relayed to LDAP or AD CS. Every read tool was registered on a read-only server, so a token
/// with no grants at all could trigger it. The spelling rules are pinned here on every OS; only the
/// Windows server applies them.
/// </remarks>
public sealed class NetworkPathTests
{
    [Theory]
    [InlineData(@"\\attacker\share\x")]
    [InlineData("//attacker/share/x")]
    [InlineData(@"\/attacker\share")]
    [InlineData(@"\\?\UNC\attacker\share\x")]
    [InlineData(@"\??\UNC\attacker\share\x")]
    [InlineData(@"\\?\GLOBALROOT\Device\Mup\attacker\share")]
    [InlineData(@"\\.\pipe\some-pipe")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"\\.\C:")]
    [InlineData(@"\\?\Volume{11111111-1111-1111-1111-111111111111}\Windows")]
    public void A_network_or_device_spelling_is_recognised_on_windows(string path)
    {
        Assert.True(NetworkPath.IsNetworkOrDevice(path, windows: true));
    }

    [Theory]
    [InlineData(@"C:\Windows\win.ini")]
    [InlineData(@"c:/Windows/win.ini")]
    [InlineData(@"\\?\C:\Windows\win.ini")]
    [InlineData(@"\\.\C:\Windows\win.ini")]
    [InlineData(@"\??\C:\Windows\win.ini")]
    [InlineData(@"\Windows\win.ini")]
    [InlineData("C:relative.txt")]
    public void A_local_drive_path_is_not_refused_however_it_is_spelled(string path)
    {
        // The long-path prefixes are how a caller reaches past MAX_PATH on a local disk: refusing them
        // would break a legitimate path for no gain.
        Assert.False(NetworkPath.IsNetworkOrDevice(path, windows: true));
    }

    [Fact]
    public void A_double_slash_off_windows_is_only_a_root_and_is_left_alone()
    {
        // POSIX lets "//" mean something implementation-defined; Linux and macOS read it as "/". Nothing
        // connects out, so the Unix servers keep their behaviour.
        Assert.False(NetworkPath.IsNetworkOrDevice("//attacker/share/x", windows: false));
    }

    [WindowsFact]
    public void Get_file_refuses_a_unc_path_without_connecting_to_it()
    {
        // 192.0.2.1 is TEST-NET-1: nothing answers, so an SMB attempt waits out its connect timeout
        // (about 20 s) before failing. Judging the path used to walk it, which is that attempt; a
        // refusal that comes back at once never opened the connection.
        var artifacts = Directory.CreateTempSubdirectory("netpath-artifacts").FullName;
        try
        {
            var sender = new FileSender(
                new FileTransferOptions(artifacts, false, false, "W=1", "WINDIAG_ALLOW_ARBITRARY_READ=1"),
                NullLogger<FileSender>.Instance);
            var clock = Stopwatch.StartNew();

            var ex = Assert.Throws<FileTransferException>(() =>
                sender.Read(new FileReadRequest(@"\\192.0.2.1\share\secret.txt"), CancellationToken.None));

            Assert.Contains("WINDIAG_ALLOW_ARBITRARY_READ=1", ex.Message, StringComparison.Ordinal);
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"Took {clock.Elapsed}: it tried to connect.");
        }
        finally
        {
            Directory.Delete(artifacts, recursive: true);
        }
    }
}
