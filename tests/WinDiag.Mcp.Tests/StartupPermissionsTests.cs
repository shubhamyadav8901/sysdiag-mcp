using WinDiag.Mcp.Hosting;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// What a service does on start when its directories can be written by someone other than an
/// administrator: put it right and say so, or refuse.
/// </summary>
/// <remarks>
/// The ACL reads and writes are injected, because the decision is where the mistakes are and the
/// decision can be tested anywhere; <see cref="ProtectedAclTests"/> covers the Windows half.
/// </remarks>
public sealed class StartupPermissionsTests
{
    private sealed class FakeDirectory
    {
        public List<string> Exposed { get; } = [];

        public bool ProtectWorks { get; init; } = true;

        public int ProtectCalls { get; private set; }

        public List<string> Warnings { get; } = [];

        public IReadOnlyList<string> Exposures(string path) => [.. Exposed];

        public void Protect(string path)
        {
            ProtectCalls++;
            if (!ProtectWorks)
            {
                throw new UnauthorizedAccessException("Attempted to perform an unauthorized operation.");
            }

            Exposed.Clear();
        }

        public void Require() => StartupPermissions.RequireProtected(
            "server directory", @"C:\WinDiag", Exposures, Protect, Warnings.Add);
    }

    [Fact]
    public void Leaves_a_directory_only_administrators_can_write_alone_and_says_nothing()
    {
        var directory = new FakeDirectory();

        directory.Require();

        Assert.Equal(0, directory.ProtectCalls);
        Assert.Empty(directory.Warnings);
    }

    [Fact]
    public void Restricts_an_exposed_directory_and_names_who_could_write_it_where_an_operator_will_look()
    {
        // The case every target bootstrapped before this release is in: C:\WinDiag inherited
        // "Authenticated Users: Modify" from C:\, and update_self is how it receives this build. A bare
        // refusal would take each of those targets off the air with nobody at its console.
        var directory = new FakeDirectory();
        directory.Exposed.Add(@"NT AUTHORITY\Authenticated Users can write to it");

        directory.Require();

        Assert.Equal(1, directory.ProtectCalls);
        var warning = Assert.Single(directory.Warnings);
        Assert.Contains(@"NT AUTHORITY\Authenticated Users", warning, StringComparison.Ordinal);
        Assert.Contains(@"C:\WinDiag", warning, StringComparison.Ordinal);

        // Restricting it closes the hole from now on; it does not undo what was planted while it was
        // open, and the operator has to be told that rather than reassured. Nor does it take back a handle a
        // user opened while they could write there; only closing it does, and a restart closes them all.
        Assert.Contains("still there", warning, StringComparison.Ordinal);
        Assert.Contains("restart the machine", warning, StringComparison.Ordinal);
    }

    [Fact]
    public void Refuses_to_start_when_restricting_the_directory_fails_and_says_why()
    {
        // A NetworkService install from an old build: the service cannot rewrite a DACL it does not own,
        // and a local user can still plant what it is about to run.
        var directory = new FakeDirectory { ProtectWorks = false };
        directory.Exposed.Add(@"BUILTIN\Users can write to it");

        var ex = Assert.Throws<ConfigurationException>(directory.Require);

        Assert.Contains(@"C:\WinDiag", ex.Message, StringComparison.Ordinal);
        Assert.Contains(@"BUILTIN\Users", ex.Message, StringComparison.Ordinal);
        Assert.Contains("unauthorized operation", ex.Message, StringComparison.Ordinal);
        Assert.Contains("--install-service", ex.Message, StringComparison.Ordinal);
        Assert.Empty(directory.Warnings);
    }

    [Fact]
    public void Refuses_to_start_when_the_directory_is_still_writable_after_restricting_it()
    {
        // The repair reporting success is not the same claim as the directory being safe: the check
        // is made again rather than trusted.
        var exposures = 0;
        var ex = Assert.Throws<ConfigurationException>(() => StartupPermissions.RequireProtected(
            "artifact directory", @"C:\WinDiagArtifacts",
            _ => { exposures++; return [@"CONTOSO\helpdesk can write to it"]; },
            _ => { },
            _ => Assert.Fail("a directory that is still exposed must not be reported as fixed")));

        Assert.Equal(2, exposures);
        Assert.Contains(@"CONTOSO\helpdesk", ex.Message, StringComparison.Ordinal);
    }

    private sealed class FakeServiceKey
    {
        public List<string> Exposed { get; } = [];

        public Exception? LookFails { get; init; }

        public bool ProtectWorks { get; init; } = true;

        public int ProtectCalls { get; private set; }

        public List<string> Warnings { get; } = [];

        public IReadOnlyList<string> Exposures(string name) => LookFails is { } failure ? throw failure : [.. Exposed];

        public void Protect(string name)
        {
            ProtectCalls++;
            if (!ProtectWorks)
            {
                throw new UnauthorizedAccessException("Attempted to perform an unauthorized operation.");
            }

            Exposed.Clear();
        }

        public void Check(bool runsAsLocalSystem, bool holdsToken = true) => StartupPermissions.ProtectServiceKey(
            "windiag", runsAsLocalSystem, Exposures, Protect, Warnings.Add, holdsToken);
    }

    [Fact]
    public void Says_nothing_when_a_service_account_that_is_not_an_administrator_is_refused_a_look_at_its_own_key()
    {
        // The installer restricts the key to SYSTEM and Administrators, so a NetworkService service is not
        // allowed even to read its ACL -- which is what a protected key looks like from there. Reported as
        // "could not check", that was an event-log warning on every start of a correctly installed service.
        var key = new FakeServiceKey { LookFails = new System.Security.SecurityException("Requested registry access is not allowed.") };

        key.Check(runsAsLocalSystem: false);

        Assert.Empty(key.Warnings);
        Assert.Equal(0, key.ProtectCalls);
    }

    [Fact]
    public void Reports_a_refused_look_from_system_because_system_can_always_read_its_own_key()
    {
        var key = new FakeServiceKey { LookFails = new UnauthorizedAccessException("Access to the registry key is denied.") };

        key.Check(runsAsLocalSystem: true);

        var warning = Assert.Single(key.Warnings);
        Assert.Contains("Could not check", warning, StringComparison.Ordinal);
        Assert.Contains("denied", warning, StringComparison.Ordinal);
    }

    [Fact]
    public void Restricts_a_key_others_can_read_and_says_the_token_must_change()
    {
        var key = new FakeServiceKey();
        key.Exposed.Add(@"BUILTIN\Users can read or change it");

        key.Check(runsAsLocalSystem: true);

        Assert.Equal(1, key.ProtectCalls);
        var warning = Assert.Single(key.Warnings);
        Assert.Contains(@"BUILTIN\Users", warning, StringComparison.Ordinal);
        Assert.Contains("now restricted", warning, StringComparison.Ordinal);
        Assert.Contains("change it", warning, StringComparison.Ordinal);
    }

    [Fact]
    public void Says_who_can_read_the_token_and_how_to_fix_it_when_the_service_cannot_restrict_its_own_key()
    {
        // A NetworkService service installed by an older build: Users can read its key, and it has no right
        // to rewrite the key's ACL. Still started -- the token was already readable, and a server that
        // will not start cannot be reached to rotate it -- but not reported as fixed, nor as unchecked.
        var key = new FakeServiceKey { ProtectWorks = false };
        key.Exposed.Add(@"BUILTIN\Users can read or change it");

        key.Check(runsAsLocalSystem: false);

        var warning = Assert.Single(key.Warnings);
        Assert.Contains(@"BUILTIN\Users", warning, StringComparison.Ordinal);
        Assert.Contains("unauthorized operation", warning, StringComparison.Ordinal);
        Assert.Contains("--install-service", warning, StringComparison.Ordinal);
        Assert.DoesNotContain("now restricted", warning, StringComparison.Ordinal);
    }

    [Fact]
    public void Restricts_a_key_others_can_read_without_asking_for_a_new_token_that_was_never_in_it()
    {
        // This build keeps the token in a key created restricted; the service key holds only grants, so an
        // exposure there is repaired and reported but is no reason to rotate anything.
        var key = new FakeServiceKey();
        key.Exposed.Add(@"BUILTIN\Users can read or change it");

        key.Check(runsAsLocalSystem: true, holdsToken: false);

        Assert.Equal(1, key.ProtectCalls);
        var warning = Assert.Single(key.Warnings);
        Assert.Contains("now restricted", warning, StringComparison.Ordinal);
        Assert.DoesNotContain("--token-stdin", warning, StringComparison.Ordinal);
        Assert.DoesNotContain("may already have the token", warning, StringComparison.Ordinal);
    }

    [Fact]
    public void Leaves_a_key_only_administrators_can_read_alone_and_says_nothing()
    {
        var key = new FakeServiceKey();

        key.Check(runsAsLocalSystem: true);

        Assert.Empty(key.Warnings);
        Assert.Equal(0, key.ProtectCalls);
    }

    [Fact]
    public void Creates_a_directory_that_is_not_there_yet_so_it_has_its_acl_from_the_start()
    {
        Assert.Equal(StartupPermissions.InstallDirectory.Create, StartupPermissions.JudgeForInstall(exists: false, [], []));
    }

    [Fact]
    public void Uses_a_directory_an_earlier_install_or_the_bootstrap_scripts_left_restricted()
    {
        // Nothing to recognise beyond that: the installer made or refused every directory it used, and the
        // service restricts both of its own on every start, so a directory windiag left reads as restricted.
        Assert.Equal(StartupPermissions.InstallDirectory.Use, StartupPermissions.JudgeForInstall(exists: true, [], []));
    }

    [Fact]
    public void Refuses_rather_than_takes_over_a_directory_others_can_change_because_their_handles_outlive_any_acl()
    {
        // A C:\WinDiag a user made before the administrator copied the server in: as its owner they can hold it
        // open for WRITE_DAC, which no share mode refuses, and put their ACE back once the installer is done.
        string[] mallory = [@"CONTOSO\mallory owns it, so can change who has access"];
        Assert.Equal(StartupPermissions.InstallDirectory.Refuse, StartupPermissions.JudgeForInstall(exists: true, mallory, mallory));

        string[] everyone = [@"NT AUTHORITY\Authenticated Users can write to it"];
        Assert.Equal(StartupPermissions.InstallDirectory.Refuse, StartupPermissions.JudgeForInstall(exists: true, everyone, everyone));
    }

    [Fact]
    public void Takes_over_a_directory_only_an_administrators_own_account_could_change_as_the_bootstrap_scripts_leave_it()
    {
        // Created restricted, then filled over the admin share by an administrator whose machine gives new files to
        // their creator: each file is owned by that account. An administrator can elevate anyway, so nothing they
        // hold is a way in, and refusing would fail every such bootstrap.
        Assert.Equal(
            StartupPermissions.InstallDirectory.TakeOver,
            StartupPermissions.JudgeForInstall(exists: true, [@"C:\WinDiag\WinDiag.Mcp.exe: CONTOSO\admin owns it, so can change who has access"], []));
    }

    [Fact]
    public void Tells_the_operator_to_rename_an_exposed_artifact_directory_aside_so_the_installer_creates_it_afresh()
    {
        var message = StartupPermissions.InstallRefusal(
            "artifact directory", @"C:\WinDiagArtifacts", [@"CONTOSO\mallory owns it, so can change who has access"], [], serverDirectory: false);

        Assert.Contains(@"CONTOSO\mallory owns it", message, StringComparison.Ordinal);
        Assert.Contains("Nothing was installed", message, StringComparison.Ordinal);
        Assert.Contains("handle", message, StringComparison.Ordinal);
        Assert.Contains(@"ren ""C:\WinDiagArtifacts"" WinDiagArtifacts.old", message, StringComparison.Ordinal);
        Assert.Contains("creates it with the ACL already on it", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Tells_the_operator_where_to_put_the_server_instead_of_a_folder_made_by_hand_under_the_drive_root()
    {
        // The installer cannot create the directory the executable is already in, so it names one that is
        // restricted from the moment it exists.
        var message = StartupPermissions.InstallRefusal(
            "server directory", @"C:\WinDiag", [@"NT AUTHORITY\Authenticated Users can write to it"], [], serverDirectory: true);

        Assert.Contains("Nothing was installed", message, StringComparison.Ordinal);
        Assert.Contains("rename it aside", message, StringComparison.Ordinal);
        Assert.Contains(@"%ProgramFiles%\WinDiag", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Does_not_suggest_renaming_aside_a_folder_that_holds_the_operators_own_files()
    {
        var message = StartupPermissions.InstallRefusal(
            "server directory", @"C:\Users\admin\Downloads", [@"CONTOSO\admin can write to it"],
            ["holiday.jpg", "setup.msi", "notes.txt", "more.txt"], serverDirectory: true);

        Assert.Contains("holiday.jpg, setup.msi, notes.txt, ...", message, StringComparison.Ordinal);
        Assert.DoesNotContain("rename it aside", message, StringComparison.Ordinal);
    }

    private sealed class FakeTempDirectory
    {
        public string? Foreign { get; set; }

        public Exception? MoveFails { get; init; }

        public List<string> Moved { get; } = [];

        public List<string> Warnings { get; } = [];

        public string Move(string path)
        {
            if (MoveFails is not null)
            {
                throw MoveFails;
            }

            Moved.Add(path);
            Foreign = null;
            return path + ".not-windiag-1";
        }

        public void Replace() => StartupPermissions.ReplaceForeign(
            "artifact directory", @"C:\Windows\Temp\windiag", _ => Foreign, Move, Warnings.Add);
    }

    [Fact]
    public void Leaves_a_default_artifact_directory_the_service_owns_and_says_nothing()
    {
        var temp = new FakeTempDirectory();

        temp.Replace();

        Assert.Empty(temp.Moved);
        Assert.Empty(temp.Warnings);
    }

    [Fact]
    public void Moves_aside_a_default_artifact_directory_a_user_made_first_rather_than_taking_it_over()
    {
        // C:\Windows\Temp lets any user create a folder, so %TEMP%\windiag may be waiting for the service.
        var temp = new FakeTempDirectory { Foreign = @"CONTOSO\mallory owns it" };

        temp.Replace();

        Assert.Equal([@"C:\Windows\Temp\windiag"], temp.Moved);
        var warning = Assert.Single(temp.Warnings);
        Assert.Contains(@"CONTOSO\mallory owns it", warning, StringComparison.Ordinal);
        Assert.Contains(@"C:\Windows\Temp\windiag.not-windiag-1", warning, StringComparison.Ordinal);
    }

    [Fact]
    public void Refuses_to_start_when_a_directory_somebody_else_made_cannot_be_moved_out_of_the_way()
    {
        // Held open without sharing delete: taking it over instead would leave them that handle.
        var temp = new FakeTempDirectory
        {
            Foreign = @"CONTOSO\mallory owns it",
            MoveFails = new IOException("The process cannot access the file because it is being used by another process.")
        };

        var ex = Assert.Throws<ConfigurationException>(temp.Replace);

        Assert.Contains("Refusing to start", ex.Message, StringComparison.Ordinal);
        Assert.Contains(@"CONTOSO\mallory owns it", ex.Message, StringComparison.Ordinal);
        Assert.Contains("being used by another process", ex.Message, StringComparison.Ordinal);
        Assert.Contains("--artifacts", ex.Message, StringComparison.Ordinal);
        Assert.Empty(temp.Warnings);
    }
}
