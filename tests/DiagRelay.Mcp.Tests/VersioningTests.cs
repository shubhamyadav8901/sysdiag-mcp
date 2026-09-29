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
