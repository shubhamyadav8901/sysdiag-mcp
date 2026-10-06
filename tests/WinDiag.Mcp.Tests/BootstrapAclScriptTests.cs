using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using WinDiag.Mcp.Hosting;

namespace WinDiag.Mcp.Tests;

/// <summary>Elevated sessions only: the script takes ownership, which an unelevated one cannot. CI's runner is elevated.</summary>
public sealed class ElevatedFactAttribute : FactAttribute
{
    public ElevatedFactAttribute()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            Skip = "Requires an elevated session, as the bootstrap scripts do.";
        }
    }
}

/// <summary>Runs tools/windiag-acl.ps1 itself, not a model of it: the scripts restrict the directories before any installer runs.</summary>
public sealed class BootstrapAclScriptTests
{
    private static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);

    [ElevatedFact]
    public void Protecting_an_existing_directory_leaves_what_was_already_in_it_writable_only_by_system_and_administrators()
    {
        // The bug this pins: each pre-existing item was given a security object with no rule added, which .NET
        // writes as "Everyone: Full Control" -- so re-running bootstrap made the server binary and handle64.exe
        // writable by every user. A file a user planted, granting Everyone write, is the case to get right.
        var root = Directory.CreateTempSubdirectory("windiag-acl-").FullName;
        try
        {
            var planted = Path.Combine(root, "handle64.exe");
            File.WriteAllText(planted, string.Empty);
            GrantEveryoneFullControl(new FileInfo(planted));
            var nested = Directory.CreateDirectory(Path.Combine(root, "nested")).FullName;
            var nestedFile = Path.Combine(nested, "self-update.cmd");
            File.WriteAllText(nestedFile, string.Empty);
            GrantEveryoneFullControl(new FileInfo(nestedFile));

            RunProtectScript(root);

            Assert.Empty(ProtectedAcl.DirectoryExposures(root, serviceAccount: null));
            foreach (var file in new[] { planted, nestedFile })
            {
                var acl = new FileInfo(file).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
                Assert.Empty(ProtectedAcl.Exposures(acl, ProtectedAcl.DirectoryWriteRights, ProtectedAcl.Trusted(null), "write to"));
                Assert.DoesNotContain(
                    acl.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(),
                    rule => rule.IdentityReference.Equals(Everyone));
                Assert.Equal(ProtectedAcl.Administrators, acl.GetOwner(typeof(SecurityIdentifier)));
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static void GrantEveryoneFullControl(FileInfo file)
    {
        var acl = file.GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(Everyone, FileSystemRights.FullControl, AccessControlType.Allow));
        file.SetAccessControl(acl);
    }

    private static void RunProtectScript(string path)
    {
        var script = ScriptPath();
        var start = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var arg in new[]
                 {
                     "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                     $"$ErrorActionPreference = 'Stop'; . '{script.Replace("'", "''")}'; Protect-WinDiagDirectory -Path '{path.Replace("'", "''")}' 3>$null",
                 })
        {
            start.ArgumentList.Add(arg);
        }

        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(TimeSpan.FromMinutes(2)), "the script did not finish");
        Assert.True(process.ExitCode == 0, $"exit {process.ExitCode}: {stdout.Result} {stderr.Result}");
    }

    private static string ScriptPath()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "tools", "windiag-acl.ps1");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException("tools/windiag-acl.ps1 not found above the test output directory.");
    }
}
