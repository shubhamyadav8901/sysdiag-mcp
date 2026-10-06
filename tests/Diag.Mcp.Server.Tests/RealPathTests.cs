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
    public void Windows_rule_stops_at_a_relative_target_instead_of_guessing_where_it_lands()
    {
        // Windows would join hop\..\.. onto A and collapse it as spelled. The walk used to do the same,
        // but .NET also hands back a junction to \Device\... as an unrooted string, and nothing tells the
        // two apart -- so an unrooted target is not followed at all, and the path is left unjudged.
        var (real, unjudged) = FileScope.Walk(Path.Combine(A, "climb", "x"), FakeLinks, windowsTargets: true, isMagicLink: null);

        Assert.True(unjudged);
        Assert.Equal(Path.Combine(A, "climb", "x"), real);
    }

    [Fact]
    public void Posix_rule_walks_a_relative_target_through_the_links_it_names()
    {
        // The kernel follows hop to A\s\d and climbs twice from there, landing back in A.
        var real = FileScope.RealPath(Path.Combine(A, "climb", "x"), FakeLinks, windowsTargets: false);

        Assert.Equal(Path.Combine(A, "x"), real);
    }

    // A\l0 -> l1 -> ... -> l{hops}, which is not a link: exactly `hops` links to follow.
    private static Func<string, string?> Chain(int hops) => path =>
    {
        var name = Path.GetFileName(path);
        return name.StartsWith('l') && int.TryParse(name.AsSpan(1), out var i) && i < hops ? $"l{i + 1}" : null;
    };

    [Fact]
    public void A_chain_of_exactly_the_kernels_link_limit_resolves()
    {
        var real = FileScope.RealPath(Path.Combine(A, "l0"), Chain(FileScope.MaxLinkHops), windowsTargets: false);

        Assert.Equal(Path.Combine(A, $"l{FileScope.MaxLinkHops}"), real);
    }

    [Fact]
    public void One_link_past_the_kernels_limit_is_refused_as_a_loop()
    {
        var ex = Assert.Throws<FileTransferException>(() =>
            FileScope.RealPath(Path.Combine(A, "l0"), Chain(FileScope.MaxLinkHops + 1), windowsTargets: false));

        Assert.Contains("link loop", ex.Message, StringComparison.Ordinal);
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
    public void A_relative_symlink_inside_an_owned_directory_is_not_owned()
    {
        // The real form of the fake above. Windows opens A\climb\x as the parent of A, outside it; and a
        // relative link that stays inside A looks, by its target text, exactly like a junction to another
        // volume. Both need the arbitrary grant.
        var owned = Directory.CreateDirectory(Path.Combine(_parent, "A")).FullName;
        Directory.CreateDirectory(Path.Combine(owned, "s", "d"));
        Directory.CreateSymbolicLink(Path.Combine(owned, "hop"), Path.Combine(owned, "s", "d"));
        Directory.CreateSymbolicLink(Path.Combine(owned, "climb"), Path.Combine("hop", "..", ".."));
        Directory.CreateSymbolicLink(Path.Combine(owned, "near"), "s");
        var server = Directory.CreateDirectory(Path.Combine(_parent, "server")).FullName;
        var options = new FileTransferOptions(owned, false, false, "W=1", "R=1");

        Assert.Equal(WriteScope.Arbitrary, FileScope.Of(Path.Combine(owned, "climb", "x"), options, server));
        Assert.Equal(WriteScope.Arbitrary, FileScope.Of(Path.Combine(owned, "near", "d", "x"), options, server));
    }
}
