using System.Diagnostics;
using WinDiag.Mcp.Hosting;
using Xunit.Abstractions;

namespace WinDiag.Mcp.OnTarget;

/// <summary>
/// Applies the installer's ACLs to a real directory under C:\ and a real service key, and reads them back.
/// </summary>
/// <remarks>
/// Self-verifying: each test first shows the object exposed -- the directory with what C:\ hands down,
/// the key with what sc.exe gives it -- so a pass cannot mean the machine was locked down to begin with.
/// Needs an elevated session, like the installer.
/// </remarks>
[Trait("Category", "OnTarget")]
public sealed class ProtectedAclTests(ITestOutputHelper output)
{
    [RequiresElevatedFact]
    public void A_folder_made_under_C_root_is_writable_by_users_until_it_is_protected()
    {
        var path = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory)!, $"windiag-acl-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        try
        {
            var before = ProtectedAcl.DirectoryExposures(path, serviceAccount: null);
            before.ToList().ForEach(output.WriteLine);
            Assert.NotEmpty(before);

            ProtectedAcl.ProtectDirectory(path, serviceAccount: null, ownedByAdministrators: true);

            Assert.Empty(ProtectedAcl.DirectoryExposures(path, serviceAccount: null));

            // And for what lands inside it afterwards, the way a staged handle64.exe or a dump does. Access
            // only: a file this elevated test writes is owned by the account running it, as a staged one is
            // owned by whoever deployed it, and neither makes the directory writable by anyone else.
            var child = Path.Combine(path, "planted.exe");
            File.WriteAllText(child, string.Empty);
            Assert.Empty(ProtectedAcl.Exposures(
                new FileInfo(child).GetAccessControl(System.Security.AccessControl.AccessControlSections.Access),
                ProtectedAcl.DirectoryWriteRights, ProtectedAcl.Trusted(null), "write to"));
        }
        finally
        {
            Directory.Delete(path, recursive: true);
        }
    }

    [RequiresElevatedFact]
    public void A_new_service_key_is_readable_by_users_until_it_is_protected()
    {
        var name = $"windiag-acl-{Guid.NewGuid():N}"[..24];
        Sc("create", name, "binPath=", Path.Combine(Environment.SystemDirectory, "cmd.exe"), "start=", "demand");
        try
        {
            var before = ProtectedAcl.ServiceKeyExposures(name);
            before.ToList().ForEach(output.WriteLine);
            Assert.NotEmpty(before);

            ProtectedAcl.ProtectServiceKey(name);

            Assert.Empty(ProtectedAcl.ServiceKeyExposures(name));
        }
        finally
        {
            Sc("delete", name);
        }
    }

    private static void Sc(params string[] arguments)
    {
        var start = new ProcessStartInfo("sc.exe") { UseShellExecute = false, RedirectStandardOutput = true };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
    }
}
