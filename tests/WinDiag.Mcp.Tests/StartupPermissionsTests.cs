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
        // open, and the operator has to be told that rather than reassured.
        Assert.Contains("still there", warning, StringComparison.Ordinal);
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
}
