using System.Text.RegularExpressions;

namespace DiagRelay.Mcp.Tests;

/// <summary>
/// The server and the relay ship as one release, so they must report one version.
/// </summary>
/// <remarks>
/// The relay was first given its own copy of the version while the release step only bumped the
/// server's, so the next release would have shipped a 2.0.0 server beside a 1.3.0 relay -- and
/// file_signatures reports that number to whoever is diagnosing a target. The version therefore lives
/// in Directory.Build.props alone, and this fails if any project grows its own copy again.
/// </remarks>
public sealed class VersioningTests
{
    [Fact]
    public void Every_project_takes_its_version_from_the_one_shared_definition()
    {
        var root = RepositoryRoot();

        var offenders = Directory.GetFiles(Path.Combine(root, "src"), "*.csproj", SearchOption.AllDirectories)
            .Concat(Directory.GetFiles(Path.Combine(root, "tests"), "*.csproj", SearchOption.AllDirectories))
            .Where(file => Regex.IsMatch(File.ReadAllText(file), @"<(Version|FileVersion|AssemblyVersion)>"))
            .Select(file => Path.GetRelativePath(root, file))
            .ToArray();

        Assert.Empty(offenders);
        Assert.Matches(@"<Version>\d+\.\d+\.\d+</Version>", File.ReadAllText(Path.Combine(root, "Directory.Build.props")));
    }

    [Fact]
    public void The_shared_definition_states_the_version_once()
    {
        // One file is not enough if it holds three numbers: a release that bumps Version and forgets
        // FileVersion ships a mismatch that file_signatures reports, with nothing going red. The SDK
        // derives both from Version, so neither may be written out as a literal.
        var props = File.ReadAllText(Path.Combine(RepositoryRoot(), "Directory.Build.props"));

        Assert.DoesNotMatch(@"<(FileVersion|AssemblyVersion)>\s*\d", props);
    }

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "WinDiag.Mcp.sln")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException($"No WinDiag.Mcp.sln above {AppContext.BaseDirectory}.");
    }
}
