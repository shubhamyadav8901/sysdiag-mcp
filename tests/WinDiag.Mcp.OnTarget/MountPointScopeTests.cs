using System.Diagnostics;
using Diag.Mcp.Core;
using Diag.Mcp.Server.Files;
using Microsoft.Extensions.Logging.Abstractions;

namespace WinDiag.Mcp.OnTarget;

/// <summary>A mounted folder inside the artifact directory does not make the volume behind it owned.</summary>
/// <remarks>
/// The unit tests drive the walk with a fake link table, because .NET's spelling of a mount point's
/// target -- <c>Volume{guid}\</c>, with the NT prefix stripped and no root -- is the whole bug, and only a
/// real mount point shows what .NET actually returns. Before the fix get_file judged
/// <c>&lt;artifacts&gt;\mnt\Windows\win.ini</c> as under the artifact directory and read the system
/// volume's file through it with no grant.
/// </remarks>
[Trait("Category", "OnTarget")]
public sealed class MountPointScopeTests : IDisposable
{
    private readonly string _artifacts = Directory.CreateTempSubdirectory("windiag-mount-scope").FullName;
    private readonly string _mount;

    public MountPointScopeTests() => _mount = Path.Combine(_artifacts, "mnt");

    public void Dispose()
    {
        if (Directory.Exists(_mount))
        {
            // Unmounted first: deleting the tree through a live mount point would walk the system volume.
            Mountvol($"\"{_mount}\" /D");
        }

        Directory.Delete(_artifacts, recursive: true);
    }

    private static string Mountvol(string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo("mountvol.exe", arguments)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        })!;
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, $"mountvol {arguments} exited {process.ExitCode}: {output}");
        return output.Trim();
    }

    [RequiresElevationFact]
    public void Get_file_through_a_mount_of_the_system_volume_in_the_artifact_directory_needs_arbitrary_read()
    {
        var systemDrive = Path.GetPathRoot(Environment.SystemDirectory)!;
        var volume = Mountvol($"{systemDrive.TrimEnd('\\')}\\ /L");
        Directory.CreateDirectory(_mount);
        Mountvol($"\"{_mount}\" {volume}");

        var through = Path.Combine(_mount, "Windows", "win.ini");
        Assert.True(File.Exists(through), "The mount point did not expose the system volume; the case was not set up.");

        var sender = new FileSender(
            new FileTransferOptions(_artifacts, false, false, "W=1", "WINDIAG_ALLOW_ARBITRARY_READ=1"),
            NullLogger<FileSender>.Instance);

        var ex = Assert.Throws<FileTransferException>(() => sender.Read(new FileReadRequest(through), CancellationToken.None));
        Assert.Contains("WINDIAG_ALLOW_ARBITRARY_READ=1", ex.Message, StringComparison.Ordinal);
    }
}
