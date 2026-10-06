using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using WinDiag.Mcp.Hosting;

namespace WinDiag.Mcp.Tests;

/// <summary>Elevated Windows sessions only: these take ownership, which an unelevated one cannot. CI's runner is elevated.</summary>
public sealed class ElevatedFactAttribute : FactAttribute
{
    public ElevatedFactAttribute()
    {
        // Asked first, because WindowsIdentity throws anywhere else, which reported these as failures
        // rather than skips when the pure tests in this project were run on a Mac or Linux.
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Requires Windows ACLs.";
            return;
        }

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
            PlantedTree.GrantEveryoneFullControl(new FileInfo(planted));
            var nested = Directory.CreateDirectory(Path.Combine(root, "nested")).FullName;
            var nestedFile = Path.Combine(nested, "self-update.cmd");
            File.WriteAllText(nestedFile, string.Empty);
            PlantedTree.GrantEveryoneFullControl(new FileInfo(nestedFile));

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

    [ElevatedFact]
    public void The_script_and_the_server_leave_the_same_owners_and_aces_on_a_directory_a_user_filled()
    {
        // One rule in two places: the script runs before anything from this repository is on the target, so
        // it cannot call the server's ProtectedAcl.ProtectDirectory. What each leaves behind must not differ.
        var byScript = PlantedTree.UnderSystemDriveRoot();
        var byServer = PlantedTree.UnderSystemDriveRoot();
        try
        {
            PlantedTree.Plant(byScript);
            PlantedTree.Plant(byServer);

            RunProtectScript(byScript);
            ProtectedAcl.ProtectDirectory(byServer, serviceAccount: null, ownedByAdministrators: true);

            Assert.Equal(Describe(byServer), Describe(byScript));
            Assert.Empty(ProtectedAcl.DirectoryExposures(byScript, serviceAccount: null));
        }
        finally
        {
            PlantedTree.Remove(byScript);
            PlantedTree.Remove(byServer);
        }
    }

    [ElevatedFact]
    public void The_script_refuses_a_directory_reached_through_a_junction_and_changes_nothing_where_it_points()
    {
        // C:\WinDiag made by a user as a junction into a folder of theirs, with the build to be staged below it.
        var target = PlantedTree.UnderSystemDriveRoot();
        var link = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory)!, $"windiag-test-{Guid.NewGuid():N}");
        try
        {
            PlantedTree.LinkDirectory(link, target);
            var before = Sddl(target);

            foreach (var path in new[] { link, Path.Combine(link, "artifacts") })
            {
                var (exit, output) = RunScript(path);
                Assert.True(exit != 0, $"the script accepted {path}: {output}");
                Assert.Contains("is a link", output, StringComparison.Ordinal);
            }

            Assert.Equal(before, Sddl(target));
            Assert.False(Directory.Exists(Path.Combine(target, "artifacts")));
        }
        finally
        {
            PlantedTree.Remove(link);
            PlantedTree.Remove(target);
        }
    }

    [ElevatedFact]
    public void The_script_refuses_a_hard_link_and_leaves_the_file_it_shares_a_name_with_as_it_was()
    {
        var path = PlantedTree.UnderSystemDriveRoot();
        var elsewhere = PlantedTree.UnderSystemDriveRoot();
        try
        {
            var original = Path.Combine(elsewhere, "original.dll");
            File.WriteAllText(original, "not windiag's");
            PlantedTree.HardLink(Path.Combine(path, "dbghelp.dll"), original);
            var before = Sddl(original);

            var (exit, output) = RunScript(path);

            Assert.True(exit != 0, $"the script accepted a hard link: {output}");
            Assert.Contains("hard link", output, StringComparison.Ordinal);
            Assert.Equal(before, Sddl(original));
        }
        finally
        {
            PlantedTree.Remove(path);
            PlantedTree.Remove(elsewhere);
        }
    }

    [ElevatedFact]
    public void The_script_creates_a_missing_directory_with_its_acl_already_on_it()
    {
        // Made by New-Item and restricted afterwards, it inherited "Authenticated Users: Modify" in between,
        // long enough for a user to open a handle that keeps that access.
        var parent = PlantedTree.UnderSystemDriveRoot();
        try
        {
            var path = Path.Combine(parent, "WinDiag");

            RunProtectScript(path);

            var acl = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
            Assert.True(acl.AreAccessRulesProtected);
            Assert.Equal(ProtectedAcl.Administrators, acl.GetOwner(typeof(SecurityIdentifier)));
            Assert.Empty(ProtectedAcl.DirectoryExposures(path, serviceAccount: null));
        }
        finally
        {
            PlantedTree.Remove(parent);
        }
    }

    [ElevatedFact]
    public void The_token_file_is_created_readable_only_by_system_and_administrators_from_its_first_byte()
    {
        // bootstrap-target writes the fleet token into the install directory for --token-stdin. Created and
        // then restricted, or inheriting from a directory a user could once write, it could be opened in
        // between -- and an open handle keeps its access whatever the ACL becomes.
        var directory = PlantedTree.UnderSystemDriveRoot();
        try
        {
            var file = Path.Combine(directory, "install-token-test.tmp");

            var (exit, output) = RunPowerShell($"New-WinDiagRestrictedFile -Path '{Quote(file)}' -Content 'the-token'");

            Assert.True(exit == 0, output);
            Assert.Equal("the-token", File.ReadAllText(file));
            var acl = new FileInfo(file).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
            Assert.True(acl.AreAccessRulesProtected);
            Assert.Equal(ProtectedAcl.Administrators, acl.GetOwner(typeof(SecurityIdentifier)));
            Assert.Equal(
                new HashSet<SecurityIdentifier> { ProtectedAcl.LocalSystem, ProtectedAcl.Administrators },
                acl.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
                    .Cast<FileSystemAccessRule>().Select(r => (SecurityIdentifier)r.IdentityReference).ToHashSet());
        }
        finally
        {
            PlantedTree.Remove(directory);
        }
    }

    [ElevatedFact]
    public void The_token_file_is_never_written_into_a_file_already_at_its_name()
    {
        // A file left at the name, by a user who could write the directory before it was restricted, is
        // theirs: writing the token into it, as WriteAllText did, handed them the token.
        var directory = PlantedTree.UnderSystemDriveRoot();
        try
        {
            var file = Path.Combine(directory, "install-token-test.tmp");
            File.WriteAllText(file, "planted");

            var (exit, _) = RunPowerShell($"New-WinDiagRestrictedFile -Path '{Quote(file)}' -Content 'the-token'");

            Assert.NotEqual(0, exit);
            Assert.Equal("planted", File.ReadAllText(file));
        }
        finally
        {
            PlantedTree.Remove(directory);
        }
    }

    /// <summary>Each item's owner, whether it inherits, and its explicit and inherited ACEs, by path below <paramref name="root"/>.</summary>
    private static string Describe(string root) =>
        string.Join(
            Environment.NewLine,
            new[] { root }.Concat(Directory.EnumerateFileSystemEntries(root, "*", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0 }))
                .Order(StringComparer.OrdinalIgnoreCase)
                .Select(path =>
                {
                    FileSystemSecurity acl = Directory.Exists(path)
                        ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner)
                        : new FileInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
                    var rules = acl.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
                        .Cast<FileSystemAccessRule>()
                        .Select(r => $"{(r.IsInherited ? "inherited" : "explicit")} {r.AccessControlType} {r.IdentityReference} {r.FileSystemRights} {r.InheritanceFlags} {r.PropagationFlags}")
                        .Order(StringComparer.Ordinal);
                    return $"{Path.GetRelativePath(root, path)}: owner {acl.GetOwner(typeof(SecurityIdentifier))}, protected {acl.AreAccessRulesProtected}; {string.Join("; ", rules)}";
                }));

    private static string Sddl(string path) =>
        (Directory.Exists(path)
            ? (FileSystemSecurity)new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner)
            : new FileInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner))
        .GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner);

    private static void RunProtectScript(string path)
    {
        var (exit, output) = RunScript(path);
        Assert.True(exit == 0, $"exit {exit}: {output}");
    }

    private static (int Exit, string Output) RunScript(string path) =>
        RunPowerShell($"Protect-WinDiagDirectory -Path '{Quote(path)}' 3>$null");

    private static string Quote(string value) => value.Replace("'", "''");

    /// <summary>Runs <paramref name="command"/> in Windows PowerShell with tools/windiag-acl.ps1 dot-sourced.</summary>
    private static (int Exit, string Output) RunPowerShell(string command)
    {
        var script = ScriptPath();
        var start = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        // Windows PowerShell builds its module path from this when it is set. Started from PowerShell 7 --
        // CI's default shell -- it inherits 7's, then fails to load 7's Microsoft.PowerShell.Security and has
        // no Set-Acl at all. An operator running the script in either shell does not hit this.
        start.Environment.Remove("PSModulePath");
        foreach (var arg in new[]
                 {
                     "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                     // The refusal's own text, unwrapped: PowerShell's error view wraps at the console width,
                     // which can split the very words a test looks for.
                     $"$ErrorActionPreference = 'Stop'; try {{ . '{Quote(script)}'; {command} }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}",
                 })
        {
            start.ArgumentList.Add(arg);
        }

        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(TimeSpan.FromMinutes(2)), "the script did not finish");
        return (process.ExitCode, $"{stdout.Result} {stderr.Result}");
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
