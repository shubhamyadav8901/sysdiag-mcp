using Microsoft.Win32;
using WinDiag.Mcp.Diagnostics.RegistryInspection;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// registry_read follows the same read gate as get_file for the hives that hold other accounts' secrets.
/// </summary>
/// <remarks>
/// It is registered under every grant, read-only included, and runs as the server's account -- usually
/// SYSTEM. Before, any token could read HKLM\SAM, HKLM\SECURITY and every loaded user's hive, while the
/// README said a read-only server could not read a single config file.
/// </remarks>
public sealed class RegistryScopeTests
{
    private const string OwnSid = "S-1-5-21-1-2-3-1001";

    [Theory]
    [InlineData(RegistryHive.LocalMachine, "SAM")]
    [InlineData(RegistryHive.LocalMachine, @"sam\SAM\Domains")]
    [InlineData(RegistryHive.LocalMachine, "SECURITY")]
    [InlineData(RegistryHive.LocalMachine, @"\Security\Policy")]
    [InlineData(RegistryHive.Users, @"S-1-5-21-9-9-9-500\Software")]
    [InlineData(RegistryHive.Users, "S-1-5-21-9-9-9-500_Classes")]
    public void Refuses_another_accounts_secrets_without_the_read_grant(RegistryHive hive, string subKey)
    {
        var ex = Assert.Throws<RegistryQueryException>(
            () => RegistryReadScope.RequireReadable(hive, subKey, allowArbitraryRead: false, OwnSid));

        Assert.Contains("--allow-arbitrary-read", ex.Message);
        Assert.Contains("WINDIAG_ALLOW_ARBITRARY_READ=1", ex.Message);
        Assert.Contains("Nothing was read", ex.Message);
    }

    [Theory]
    [InlineData(RegistryHive.LocalMachine, "SAM")]
    [InlineData(RegistryHive.LocalMachine, "SECURITY")]
    [InlineData(RegistryHive.Users, @"S-1-5-21-9-9-9-500\Software")]
    public void Reads_them_with_the_grant(RegistryHive hive, string subKey)
    {
        RegistryReadScope.RequireReadable(hive, subKey, allowArbitraryRead: true, OwnSid);
    }

    [Theory]
    [InlineData(RegistryHive.LocalMachine, "")]
    [InlineData(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft")]
    [InlineData(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services")]
    [InlineData(RegistryHive.LocalMachine, "SAMPLE_VENDOR")]
    [InlineData(RegistryHive.CurrentUser, @"Software\Vendor")]
    [InlineData(RegistryHive.ClassesRoot, ".txt")]
    [InlineData(RegistryHive.CurrentConfig, "System")]
    [InlineData(RegistryHive.Users, "")]
    [InlineData(RegistryHive.Users, @".DEFAULT\Software")]
    [InlineData(RegistryHive.Users, @"S-1-5-18\Software")]
    [InlineData(RegistryHive.Users, "S-1-5-19")]
    [InlineData(RegistryHive.Users, "S-1-5-20")]
    [InlineData(RegistryHive.Users, @"S-1-5-21-1-2-3-1001\Software")]
    [InlineData(RegistryHive.Users, "S-1-5-21-1-2-3-1001_Classes")]
    public void Reads_the_machine_configuration_and_its_own_hive_without_any_grant(RegistryHive hive, string subKey)
    {
        // What registry_read is for. Listing HKU itself only names the SIDs, which process_list shows anyway.
        RegistryReadScope.RequireReadable(hive, subKey, allowArbitraryRead: false, OwnSid);
    }
}

/// <summary>registry_read never returns a credential, whatever grant the server has.</summary>
/// <remarks>
/// A windiag service keeps its bearer token in its own key's Environment value. Two instances on one machine
/// is a documented setup -- a read-only one beside a full one -- and the read-only token could read the full
/// instance's token from that value, which turned it into the full instance's authority.
/// </remarks>
public sealed class RegistryRedactionTests
{
    [Fact]
    public void Redacts_every_token_in_a_service_environment_block()
    {
        var (rendered, _) = WindowsRegistryInspector.RenderValue(
            "Environment",
            new[] { "WINDIAG_TOKEN=0123456789abcdef", "WINDIAG_ALLOW_ARBITRARY_READ=1", "OTHER_API_TOKEN=xyz" });

        Assert.DoesNotContain("0123456789abcdef", rendered);
        Assert.DoesNotContain("xyz", rendered);
        Assert.Contains("WINDIAG_TOKEN=(redacted)", rendered);
        Assert.Contains("WINDIAG_ALLOW_ARBITRARY_READ=1", rendered);
    }

    [Theory]
    [InlineData("WINDIAG_TOKEN")]
    [InlineData("DefaultPassword")]
    [InlineData("ClientSecret")]
    public void Redacts_a_string_value_named_like_a_credential(string name)
    {
        var (rendered, size) = WindowsRegistryInspector.RenderValue(name, "hunter2-value");

        Assert.DoesNotContain("hunter2-value", rendered);
        Assert.Contains("redacted", rendered);
        Assert.True(size > 0, "the stored size should still be reported, so a set value reads as set");
    }

    [Fact]
    public void Leaves_a_number_named_like_a_credential_alone()
    {
        // A DWORD such as DisablePasswordChange is a setting, not a secret, and hiding it hides the answer.
        var (rendered, _) = WindowsRegistryInspector.RenderValue("DisablePasswordChange", 1);

        Assert.Contains("1 (0x1)", rendered);
    }

    [Fact]
    public void Leaves_ordinary_values_alone()
    {
        Assert.Equal(@"C:\App", WindowsRegistryInspector.RenderValue("InstallPath", @"C:\App").Rendered);
    }
}
