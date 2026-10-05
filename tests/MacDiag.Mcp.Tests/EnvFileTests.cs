using System.Collections;
using MacDiag.Mcp.Configuration;

namespace MacDiag.Mcp.Tests;

public sealed class EnvFileTests
{
    [Fact]
    public void Key_value_lines_are_read_and_comments_blanks_and_malformed_lines_are_ignored()
    {
        var values = EnvFile.Parse("# macdiag\nMACDIAG_TOKEN=abc=def\n\nMACDIAG_READ_ONLY=1\r\nnot a pair\n =x\n");

        Assert.Equal("abc=def", values["MACDIAG_TOKEN"]);
        Assert.Equal("1", values["MACDIAG_READ_ONLY"]);
        Assert.Equal(2, values.Count);
    }

    [Fact]
    public void The_env_file_wins_over_the_process_environment_for_the_keys_it_names()
    {
        var merged = EnvFile.Over(new Hashtable { ["MACDIAG_READ_ONLY"] = "0", ["HOME"] = "/var/root" },
            new Dictionary<string, string> { ["MACDIAG_READ_ONLY"] = "1" });

        Assert.Equal("1", merged["MACDIAG_READ_ONLY"]);
        Assert.Equal("/var/root", merged["HOME"]);
    }

    [Fact]
    public void Options_read_from_the_merged_environment_carry_the_label_and_protected_labels()
    {
        var options = MacDiagOptions.FromEnvironment(new Hashtable
        {
            ["MACDIAG_SERVICE_LABEL"] = "com.sysdiag.macdiag",
            ["MACDIAG_PROTECTED_LABELS"] = " com.example.agent , org.example.vpn ,",
        });

        Assert.Equal("com.sysdiag.macdiag", options.ServiceLabel);
        Assert.Equal(["com.example.agent", "org.example.vpn"], options.ProtectedLabels);
        Assert.Equal("/var/db/macdiag", options.ArtifactDirectory);
        Assert.DoesNotContain("secret", MacDiagOptions.FromEnvironment(new Hashtable { ["MACDIAG_TOKEN"] = "secret" }).ToString(), StringComparison.Ordinal);
    }
}
