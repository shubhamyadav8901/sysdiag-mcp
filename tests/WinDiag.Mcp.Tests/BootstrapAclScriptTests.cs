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

/// <summary>The theory form of <see cref="ElevatedFactAttribute"/>.</summary>
public sealed class ElevatedTheoryAttribute : TheoryAttribute
{
    public ElevatedTheoryAttribute() => Skip = new ElevatedFactAttribute().Skip;
}

/// <summary>
/// <see cref="ElevatedTheoryAttribute"/>, where this machine's own admin share answers too: how bootstrap-target.ps1
/// and deploy-target.ps1 reach a target, here pointed back at this machine.
/// </summary>
public sealed class ElevatedAdminShareTheoryAttribute : TheoryAttribute
{
    public ElevatedAdminShareTheoryAttribute() =>
        Skip = new ElevatedFactAttribute().Skip
            ?? (Directory.Exists(BootstrapAclScriptTests.OverAdminShare(Path.GetPathRoot(Environment.SystemDirectory)!))
                ? null
                : "Requires this machine's admin share, which the Server service publishes.");
}

/// <summary>Runs tools/windiag-acl.ps1 itself, not a model of it: the scripts restrict the directories before any installer runs.</summary>
public sealed class BootstrapAclScriptTests
{
    /// <summary><paramref name="localPath"/> as bootstrap-target.ps1 reaches it: <c>C:\x</c> as <c>\\localhost\C$\x</c>.</summary>
    internal static string OverAdminShare(string localPath) => $@"\\localhost\{localPath[0]}${localPath[2..]}";

    [ElevatedTheory]
    [InlineData("powershell.exe")]
    [InlineData("pwsh.exe")]
    public void Only_a_path_on_this_machines_own_disk_is_judged_by_this_machines_administrators(string shell)
    {
        // The choice Protect-WinDiagDirectory makes before trusting the local Administrators group's members above
        // a directory. Over the admin share, or anything else not plainly a local disk, the ACLs read are another
        // machine's, and a member of this machine's group may be nobody there.
        var local = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory)!, "WinDiag");
        var paths = new[] { local, OverAdminShare(local), $@"\\{Environment.MachineName}\{local[0]}${local[2..]}", $@"\\?\{local}" };

        var (exit, output) = RunPowerShell(
            string.Join("; ", paths.Select(path => $"[Console]::Out.WriteLine('{Quote(path)} ' + (Test-WinDiagOwnDisk '{Quote(path)}'))")),
            shell);

        Assert.True(exit == 0, output);
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        Assert.Contains($"{local} True", lines);
        Assert.All(paths.Skip(1), path => Assert.Contains($"{path} False", lines));
    }

    [ElevatedAdminShareTheory]
    [InlineData("powershell.exe")]
    [InlineData("pwsh.exe")]
    public void Over_the_admin_share_the_script_refuses_a_path_below_a_directory_an_individual_administrator_owns(string shell)
    {
        // bootstrap-target -RemotePath D:\Ops\WinDiag, run from a workstation where CORP\bob is a direct member of
        // the local Administrators group, against a target where he is an ordinary user who owns D:\Ops. Judged
        // by the workstation's group, the path passed; bob renames D:\Ops after staging and puts his own build in
        // its place for PsExec to run as SYSTEM. Here both machines are this one, so the owner really is an
        // administrator -- which is the point: over the share the script cannot tell, and must not trust it.
        using var admin = new TemporaryLocalUser(administrator: true);
        var parent = PlantedTree.UnderSystemDriveRoot();
        try
        {
            ProtectedAcl.ProtectDirectory(parent, serviceAccount: null, ownedByAdministrators: true);

            // Owned by the group, the route itself works: the directory is created through the share.
            var accepted = Path.Combine(parent, "WinDiag");
            var (exit, output) = RunPowerShell($"Protect-WinDiagDirectory -Path '{Quote(OverAdminShare(accepted))}'", shell);
            Assert.True(exit == 0, output);
            Assert.True(Directory.Exists(accepted));

            PlantedTree.SetOwner(parent, admin.Sid);
            var path = Path.Combine(parent, "WinDiagArtifacts");
            var (refused, refusal) = RunPowerShell($"Protect-WinDiagDirectory -Path '{Quote(OverAdminShare(path))}'", shell);
            Assert.True(refused != 0, $"over the admin share, the script took this machine's administrators for the target's: {refusal}");
            Assert.Contains($"{OverAdminShare(parent)}, on the way to it: ", refusal, StringComparison.Ordinal);
            Assert.Contains($"{admin.Name} owns it", refusal, StringComparison.Ordinal);
            Assert.Contains("even an administrator of the target", refusal, StringComparison.Ordinal);
            Assert.False(Directory.Exists(path));

            // And the same directory, judged where it is, passes: the refusal is the route's, not the owner's.
            var (local, localOutput) = RunPowerShell($"Protect-WinDiagDirectory -Path '{Quote(path)}'", shell);
            Assert.True(local == 0, localOutput);
        }
        finally
        {
            PlantedTree.Remove(parent);
        }
    }

    [ElevatedTheory]
    [InlineData("powershell.exe")]
    [InlineData("pwsh.exe")]
    public void The_script_refuses_an_existing_directory_others_can_write_and_changes_nothing_in_it(string shell)
    {
        // A C:\WinDiag a user made and filled, or one an older bootstrap left open. Taking it over by path --
        // what the script did -- could be made to land elsewhere between each check and each Set-Acl by whoever
        // still owned what was inside; the script now leaves that to the server, which works through handles.
        var path = PlantedTree.UnderSystemDriveRoot();
        try
        {
            var planted = PlantedTree.Plant(path);
            var before = Describe(path);

            var (exit, output) = RunPowerShell($"Protect-WinDiagDirectory -Path '{Quote(path)}'", shell);

            Assert.True(exit != 0, $"the script accepted a directory others can write: {output}");
            Assert.Contains("can write to it", output, StringComparison.Ordinal);
            Assert.Contains("Nothing was changed", output, StringComparison.Ordinal);
            Assert.Equal(before, Describe(path));
            Assert.All(planted, file => Assert.Equal("planted", File.ReadAllText(file)));
        }
        finally
        {
            PlantedTree.Remove(path);
        }
    }

    [ElevatedTheory]
    [InlineData("powershell.exe")]
    [InlineData("pwsh.exe")]
    public void The_script_uses_a_directory_the_server_has_already_protected_and_changes_nothing_in_it(string shell)
    {
        // Re-running bootstrap against a target windiag already runs from: the installer, or the service's own
        // start, restricted the directory and took over what it held. The script judges it through a handle
        // and goes on.
        var path = PlantedTree.UnderSystemDriveRoot();
        try
        {
            PlantedTree.Plant(path);
            ProtectedAcl.ProtectDirectory(path, serviceAccount: null, ownedByAdministrators: true);
            var before = Describe(path);

            var (exit, output) = RunPowerShell($"Protect-WinDiagDirectory -Path '{Quote(path)}'", shell);

            Assert.True(exit == 0, output);
            Assert.Equal(before, Describe(path));
        }
        finally
        {
            PlantedTree.Remove(path);
        }
    }

    [ElevatedTheory]
    [InlineData("powershell.exe")]
    [InlineData("pwsh.exe")]
    public void The_script_refuses_a_path_below_a_directory_any_user_can_rename_and_creates_nothing_there(string shell)
    {
        // -RemotePath C:\Tools\WinDiag with C:\Tools made under C:\: any user can rename C:\Tools and put their
        // own in its place after staging, and PsExec would then run their WinDiag.Mcp.exe as SYSTEM.
        var parent = PlantedTree.UnderSystemDriveRoot();
        try
        {
            var path = Path.Combine(parent, "WinDiag");

            var (exit, output) = RunPowerShell($"Protect-WinDiagDirectory -Path '{Quote(path)}'", shell);

            Assert.True(exit != 0, $"the script accepted a path below a directory any user can rename: {output}");
            Assert.Contains($"{parent}, on the way to it:", output, StringComparison.Ordinal);
            Assert.False(Directory.Exists(path));
        }
        finally
        {
            PlantedTree.Remove(parent);
        }
    }

    [ElevatedTheory]
    [InlineData("powershell.exe")]
    [InlineData("pwsh.exe")]
    public void The_script_accepts_a_path_below_a_directory_an_individual_administrator_owns_and_only_administrators_can_change(string shell)
    {
        // -RemotePath D:\Ops\WinDiag on a server whose D:\Ops the built-in Administrator made and locked down:
        // owned by that account, not the group. The server trusts it above its directories; so must the script,
        // or bootstrap refuses what the service it installs then accepts. An ordinary user's is still refused.
        using var admin = new TemporaryLocalUser(administrator: true);
        using var user = new TemporaryLocalUser(administrator: false);
        var parent = PlantedTree.UnderSystemDriveRoot();
        try
        {
            ProtectedAcl.ProtectDirectory(parent, serviceAccount: null, ownedByAdministrators: true);
            var path = Path.Combine(parent, "WinDiag");

            PlantedTree.SetOwner(parent, user.Sid);
            var (refused, refusal) = RunPowerShell($"Protect-WinDiagDirectory -Path '{Quote(path)}'", shell);
            Assert.True(refused != 0, $"the script accepted a path below a directory an ordinary user owns: {refusal}");
            Assert.Contains($"{user.Name} owns it", refusal, StringComparison.Ordinal);
            Assert.Contains("/setowner *S-1-5-32-544", refusal, StringComparison.Ordinal);
            Assert.False(Directory.Exists(path));

            PlantedTree.SetOwner(parent, admin.Sid);
            var (exit, output) = RunPowerShell($"Protect-WinDiagDirectory -Path '{Quote(path)}'", shell);
            Assert.True(exit == 0, output);
            Assert.True(Directory.Exists(path));
        }
        finally
        {
            PlantedTree.Remove(parent);
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
    public void The_script_refuses_a_directory_others_can_write_without_changing_a_file_hard_linked_into_it()
    {
        // The takeover the script used to do would have handed the file behind a hard link to Administrators,
        // and PowerShell's own test for one gives up on a file someone holds open. Now nothing in a directory
        // that exists is changed at all.
        var path = PlantedTree.UnderSystemDriveRoot();
        var elsewhere = PlantedTree.UnderSystemDriveRoot();
        try
        {
            var original = Path.Combine(elsewhere, "original.dll");
            File.WriteAllText(original, "not windiag's");
            PlantedTree.HardLink(Path.Combine(path, "dbghelp.dll"), original);
            var before = Sddl(original);

            var (exit, output) = RunScript(path);

            Assert.True(exit != 0, $"the script accepted a directory others can write: {output}");
            Assert.Equal(before, Sddl(original));
        }
        finally
        {
            PlantedTree.Remove(path);
            PlantedTree.Remove(elsewhere);
        }
    }

    [ElevatedTheory]
    [InlineData("powershell.exe")]
    [InlineData("pwsh.exe")]
    public void The_script_creates_a_missing_directory_with_its_acl_already_on_it(string shell)
    {
        // Made by New-Item and restricted afterwards, it inherited "Authenticated Users: Modify" in between,
        // long enough for a user to open a handle that keeps that access. Two levels are missing, as with a
        // -RemotePath of C:\Tools\WinDiag on a machine without C:\Tools.
        var parent = PlantedTree.UnderSystemDriveRoot();
        try
        {
            // Below a directory only administrators can change; one any user could rename is refused, above.
            ProtectedAcl.ProtectDirectory(parent, serviceAccount: null, ownedByAdministrators: true);
            var path = Path.Combine(parent, "Tools", "WinDiag");

            var (exit, output) = RunPowerShell($"Protect-WinDiagDirectory -Path '{Quote(path)}'", shell);

            Assert.True(exit == 0, output);

            foreach (var made in new[] { Path.GetDirectoryName(path)!, path })
            {
                var acl = new DirectoryInfo(made).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
                Assert.True(acl.AreAccessRulesProtected);
                Assert.Equal(ProtectedAcl.Administrators, acl.GetOwner(typeof(SecurityIdentifier)));
            }

            Assert.Empty(ProtectedAcl.DirectoryExposures(path, serviceAccount: null));
        }
        finally
        {
            PlantedTree.Remove(parent);
        }
    }

    // Both shells, because the scripts take a different path to the same API in each: Windows PowerShell has
    // .NET Framework's FileStream and Directory overloads that take an ACL, PowerShell 7 the extension methods.
    [ElevatedTheory]
    [InlineData("powershell.exe")]
    [InlineData("pwsh.exe")]
    public void The_token_file_is_created_readable_only_by_system_and_administrators_from_its_first_byte(string shell)
    {
        // bootstrap-target writes the fleet token into the install directory for --token-stdin. Created and
        // then restricted, or inheriting from a directory a user could once write, it could be opened in
        // between -- and an open handle keeps its access whatever the ACL becomes.
        var directory = PlantedTree.UnderSystemDriveRoot();
        try
        {
            var file = Path.Combine(directory, "install-token-test.tmp");

            var (exit, output) = RunPowerShell($"New-WinDiagRestrictedFile -Path '{Quote(file)}' -Content 'the-token'", shell);

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

    [ElevatedTheory]
    [InlineData("powershell.exe")]
    [InlineData("pwsh.exe")]
    public void The_token_file_is_never_written_into_a_file_already_at_its_name(string shell)
    {
        // A file left at the name, by a user who could write the directory before it was restricted, is
        // theirs: writing the token into it, as WriteAllText did, handed them the token.
        var directory = PlantedTree.UnderSystemDriveRoot();
        try
        {
            var file = Path.Combine(directory, "install-token-test.tmp");
            File.WriteAllText(file, "planted");

            var (exit, _) = RunPowerShell($"New-WinDiagRestrictedFile -Path '{Quote(file)}' -Content 'the-token'", shell);

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

    private static (int Exit, string Output) RunScript(string path) =>
        RunPowerShell($"Protect-WinDiagDirectory -Path '{Quote(path)}'");

    private static string Quote(string value) => value.Replace("'", "''");

    /// <summary>Runs <paramref name="command"/> in <paramref name="shell"/> with tools/windiag-acl.ps1 dot-sourced.</summary>
    private static (int Exit, string Output) RunPowerShell(string command, string shell = "powershell.exe")
    {
        var script = ScriptPath();
        var start = new ProcessStartInfo(shell)
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

    internal static string ScriptPath()
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
