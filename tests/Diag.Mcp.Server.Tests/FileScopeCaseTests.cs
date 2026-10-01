using System.Runtime.Versioning;
using Diag.Mcp.Server.Files;

namespace Diag.Mcp.Server.Tests;

public sealed class FileScopeCaseTests
{
    [Theory]
    [InlineData("/Library/PrivilegedHelperTools/com.windiag.macdiag/x", "/Library/PrivilegedHelperTools/com.windiag.macdiag", true)]
    [InlineData("/Library/PrivilegedHelperTools/COM.WINDIAG.MACDIAG/x", "/Library/PrivilegedHelperTools/com.windiag.macdiag", true)]
    [InlineData("/var/db/café/x", "/var/db/café", true)] // decomposed against composed e-acute
    [InlineData("/Library/PrivilegedHelperTool\u017F/com.windiag.macdiag/x", "/Library/PrivilegedHelperTools/com.windiag.macdiag", true)] // long s, which APFS folds to s
    [InlineData("/var/db/other/x", "/var/db/macdiag", false)]
    [InlineData("/var/db/macdiagx", "/var/db/macdiag", false)]
    public void The_loose_comparison_ignores_case_and_unicode_normalisation_only(string candidate, string directory, bool under)
    {
        Assert.Equal(under, FileScope.LooseIsUnder(candidate, directory, normalizationWorks: true));
    }

    [Theory]
    [InlineData("/var/db/café/x", "/var/db/café", true)]
    [InlineData("/var/db/MACDIAG/x", "/var/db/macdiag", true)]
    [InlineData("/var/db/otheré/x", "/var/db/macdiag", false)]
    [InlineData("/var/db/other/x", "/var/db/macdiag", false)]
    public void Without_normalisation_a_non_ascii_spelling_that_might_be_the_directory_counts_as_under_it(
        string candidate, string directory, bool under)
    {
        // Invariant globalization turns Normalize into a silent no-op; the gate must then fail closed.
        Assert.Equal(under, FileScope.LooseIsUnder(candidate, directory, normalizationWorks: false));
    }

    [UnixFact]
    [UnsupportedOSPlatform("windows")]
    public void A_case_variant_of_the_server_directory_needs_the_self_update_grant_but_is_not_owned()
    {
        // Review Focus 2. On case-insensitive APFS the variant is the server's directory, so staging there
        // must need the grant; on a case-sensitive volume it is a different directory, so it must not be owned.
        var root = Directory.CreateTempSubdirectory("fsc-").FullName;
        try
        {
            var server = Directory.CreateDirectory(Path.Combine(root, "macdiag")).FullName;
            var artifacts = Directory.CreateDirectory(Path.Combine(root, "art")).FullName;
            var options = new FileTransferOptions(artifacts, false, false, "W=1", "R=1", ServerDirectoryWritable: false, ServerDirectorySetting: "S=1");
            var variant = Path.Combine(root, "MacDiag", "x");

            var (scope, inServer) = FileScope.Classify(variant, options, server, replacesFinalLink: false, looseServerMatch: true);

            Assert.True(inServer);                     // the gate applies
            if (!OperatingSystem.IsMacOS())
            {
                Assert.Equal(WriteScope.Arbitrary, scope); // and on a case-sensitive volume it is not owned
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
