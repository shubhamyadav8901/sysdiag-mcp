using Diag.Mcp.Server.Files;

namespace Diag.Mcp.Server.Tests;

/// <summary>How a relative link target is followed differs by OS, and the real path must follow the OS it runs on.</summary>
/// <remarks>
/// The fake link table stands in for the filesystem, so both rules are exercised on every machine:
/// creating a real symlink on Windows needs developer mode or a privilege most machines lack.
/// </remarks>
public sealed class RealPathTests
{
    // Never touched on disk: the fake answers every link lookup.
    private static readonly string A = Path.Combine(Path.GetTempPath(), "realpath-fake-owned");

    // A\hop -> A\s\d, and A\climb -> hop\..\.. (relative).
    private static string? FakeLinks(string path) =>
        path == Path.Combine(A, "hop") ? Path.Combine(A, "s", "d")
        : path == Path.Combine(A, "climb") ? Path.Combine("hop", "..", "..")
        : null;

    [Fact]
    public void Windows_rule_collapses_a_relative_targets_dotdot_by_spelling_against_the_links_directory()
    {
        // Windows joins hop\..\.. onto A and collapses it as spelled: the parent of A. It never goes
        // through hop, so hop pointing deep inside A cannot pull the answer back under A.
        var real = FileScope.RealPath(Path.Combine(A, "climb", "x"), FakeLinks, relativeTargetsBySpelling: true);

        Assert.Equal(Path.Combine(Path.GetDirectoryName(A)!, "x"), real);
        Assert.False(FileScope.IsUnder(real, A));
    }

    [Fact]
    public void Posix_rule_walks_a_relative_target_through_the_links_it_names()
    {
        // The kernel follows hop to A\s\d and climbs twice from there, landing back in A.
        var real = FileScope.RealPath(Path.Combine(A, "climb", "x"), FakeLinks, relativeTargetsBySpelling: false);

        Assert.Equal(Path.Combine(A, "x"), real);
    }
}

/// <summary>A Windows fact that needs to create a symbolic link, and reports itself skipped where it cannot.</summary>
/// <remarks>
/// Probed once by creating a real link, not inferred from developer mode or group membership: either
/// can be granted by policy, and the probe is the only answer that cannot be wrong.
/// </remarks>
public sealed class WindowsSymlinkFactAttribute : FactAttribute
{
    private static readonly Lazy<bool> CanCreate = new(Probe);

    public WindowsSymlinkFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Windows only.";
        }
        else if (!CanCreate.Value)
        {
            Skip = "Creating a symbolic link needs developer mode or SeCreateSymbolicLinkPrivilege.";
        }
    }

    private static bool Probe()
    {
        var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"symlink-probe-{Guid.NewGuid():N}")).FullName;
        try
        {
            Directory.CreateSymbolicLink(Path.Combine(dir, "probe"), "target");
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }
}

public sealed class WindowsRelativeSymlinkScopeTests : IDisposable
{
    private readonly string _parent = Directory.CreateDirectory(
        Path.Combine(Path.GetTempPath(), $"windiag-relsym-{Guid.NewGuid():N}")).FullName;

    public void Dispose()
    {
        try { Directory.Delete(_parent, recursive: true); } catch (IOException) { }
    }

    [WindowsSymlinkFact]
    public void A_relative_symlink_that_climbs_by_spelling_is_judged_where_Windows_lands()
    {
        // The real form of the fake above: Windows opens A\climb\x as the parent of A, outside it.
        var owned = Directory.CreateDirectory(Path.Combine(_parent, "A")).FullName;
        Directory.CreateDirectory(Path.Combine(owned, "s", "d"));
        Directory.CreateSymbolicLink(Path.Combine(owned, "hop"), Path.Combine(owned, "s", "d"));
        Directory.CreateSymbolicLink(Path.Combine(owned, "climb"), Path.Combine("hop", "..", ".."));

        var real = FileScope.RealPath(Path.Combine(owned, "climb", "x"));

        Assert.Equal(Path.Combine(_parent, "x"), real, ignoreCase: true);
    }
}
