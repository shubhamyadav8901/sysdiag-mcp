using Microsoft.Win32;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.RegistryInspection;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

public sealed class RegistryPathTests
{
    [Theory]
    [InlineData(@"HKLM\SOFTWARE\Vendor", RegistryHive.LocalMachine, @"SOFTWARE\Vendor")]
    [InlineData(@"HKEY_LOCAL_MACHINE\SOFTWARE", RegistryHive.LocalMachine, "SOFTWARE")]
    [InlineData(@"hkcu\Software\X", RegistryHive.CurrentUser, @"Software\X")]
    [InlineData("HKCR", RegistryHive.ClassesRoot, "")]
    [InlineData(@"HKU\.DEFAULT", RegistryHive.Users, ".DEFAULT")]
    [InlineData(@"HKCC\System", RegistryHive.CurrentConfig, "System")]
    public void Splits_a_path_into_its_hive_and_subkey(string path, RegistryHive hive, string subKey)
    {
        var parsed = RegistryPath.Split(path);

        Assert.Equal(hive, parsed.Hive);
        Assert.Equal(subKey, parsed.SubKey);
    }

    [Fact]
    public void Accepts_forward_slashes_and_a_trailing_separator()
    {
        // Both turn up in pasted paths and in documentation, and neither is worth a refusal.
        Assert.Equal(@"SOFTWARE\Vendor", RegistryPath.Split("HKLM/SOFTWARE/Vendor/").SubKey);
    }

    [Fact]
    public void Refuses_something_that_is_not_a_hive()
    {
        var ex = Assert.Throws<RegistryPathException>(() => RegistryPath.Split(@"HKXX\Software"));

        Assert.Contains("HKLM", ex.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("native")]
    [InlineData("default")]
    public void Defaults_to_the_view_the_operating_system_uses(string? view)
    {
        // NOT RegistryView.Default, which means "whatever bitness this process is" -- that is how the
        // win-x86 build would silently read WOW6432Node and report it as HKLM\SOFTWARE.
        Assert.Equal(RegistryPath.NativeView, RegistryPath.ParseView(view));
        Assert.NotEqual(RegistryView.Default, RegistryPath.ParseView(view));
    }

    [Theory]
    [InlineData("64", RegistryView.Registry64)]
    [InlineData("x64", RegistryView.Registry64)]
    [InlineData("32", RegistryView.Registry32)]
    [InlineData("wow64", RegistryView.Registry32)]
    public void Maps_the_documented_view_names(string view, RegistryView expected)
    {
        Assert.Equal(expected, RegistryPath.ParseView(view));
    }

    [Fact]
    public void Refuses_a_view_it_does_not_know()
    {
        var ex = Assert.Throws<RegistryPathException>(() => RegistryPath.ParseView("both"));

        Assert.Contains("WOW6432Node", ex.Message);
    }

    [Fact]
    public void Names_the_view_it_read_so_an_answer_is_never_ambiguous()
    {
        if (!Environment.Is64BitOperatingSystem)
        {
            return; // Covered by the single-view test below, which is the only case that applies here.
        }

        Assert.Equal("32-bit (WOW6432Node)", RegistryPath.Describe(RegistryView.Registry32));
        Assert.Equal("64-bit", RegistryPath.Describe(RegistryView.Registry64));
    }

    [Fact]
    public void Never_calls_the_only_view_on_32_bit_windows_the_wow6432node_one()
    {
        // Found live on the 32-bit target, which reported "[32-bit (WOW6432Node) view]" for every key.
        // There is no WOW6432Node on 32-bit Windows -- there is one registry -- so that label tells a
        // reader they are looking at a redirected copy and sends them hunting for a real key that does
        // not exist. The expectation is written against Is64BitOperatingSystem rather than derived
        // from Describe, because deriving it is what made the original test unable to see this.
        var described = RegistryPath.Describe(RegistryPath.NativeView);

        if (Environment.Is64BitOperatingSystem)
        {
            Assert.Equal("64-bit", described);
        }
        else
        {
            Assert.DoesNotContain("WOW6432Node", described);
            Assert.Contains("only one", described);
        }
    }

    [Fact]
    public void Refuses_a_view_this_machine_does_not_have()
    {
        if (Environment.Is64BitOperatingSystem)
        {
            Assert.Equal(RegistryView.Registry64, RegistryPath.ParseView("64"));
            return;
        }

        // Windows accepts Registry64 on 32-bit Windows and ignores it, so honouring the request would
        // return the only view under a label saying otherwise.
        var ex = Assert.Throws<RegistryPathException>(() => RegistryPath.ParseView("64"));

        Assert.Contains("one registry rather than two", ex.Message);
    }
}

/// <summary>
/// The inspector against this machine's real registry.
/// </summary>
/// <remarks>
/// Reads only, and only keys that exist on every Windows install, so it needs no fixture and no
/// elevation.
/// </remarks>
public sealed class RegistryInspectorTests
{
    private static WindowsRegistryInspector Inspector(int maxResults = 200) =>
        new(WinDiagOptions.FromEnvironment(new System.Collections.Hashtable
        {
            ["WINDIAG_MAX_RESULTS"] = maxResults.ToString()
        }));

    [Fact]
    public void Reads_values_and_their_types_from_a_key_every_machine_has()
    {
        var result = Inspector().Read(
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", null, null, CancellationToken.None);

        var build = result.Values.Single(v => v.Name == "CurrentBuild");

        Assert.Equal("REG_SZ", build.Kind);
        Assert.False(string.IsNullOrWhiteSpace(build.Value));
        Assert.NotEmpty(result.SubKeyNames);
    }

    [Fact]
    public void Renders_a_dword_in_both_decimal_and_hex()
    {
        // Registry numbers are documented either way depending on who wrote the documentation, and
        // converting by hand is where a comparison against a known-good machine goes wrong.
        var result = Inspector().Read(
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentMajorVersionNumber", null,
            CancellationToken.None);

        var value = Assert.Single(result.Values);

        Assert.Equal("REG_DWORD", value.Kind);
        Assert.Contains("0x", value.Value);
    }

    [Fact]
    public void Reads_a_single_named_value_without_returning_the_rest()
    {
        var result = Inspector().Read(
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild", null,
            CancellationToken.None);

        Assert.Single(result.Values);
    }

    [Fact]
    public void Distinguishes_a_missing_value_from_an_empty_key()
    {
        // "The value is not set" and "the key holds nothing" lead somewhere different, and the caller
        // asked about one value.
        var ex = Assert.Throws<RegistryQueryException>(() => Inspector().Read(
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            $"windiag-absent-{Guid.NewGuid():N}", null, CancellationToken.None));

        Assert.Contains("has no value named", ex.Message);
    }

    [Fact]
    public void Points_at_the_other_view_when_a_key_is_not_in_this_one()
    {
        // The most common reason a key looks missing, and the caller cannot see the view from the path
        // they typed.
        var ex = Assert.Throws<RegistryQueryException>(() => Inspector().Read(
            $@"HKLM\SOFTWARE\windiag-absent-{Guid.NewGuid():N}", null, null, CancellationToken.None));

        Assert.Contains("does not exist", ex.Message);

        if (Environment.Is64BitOperatingSystem)
        {
            Assert.Contains("WOW6432Node", ex.Message);
        }
    }

    [Fact]
    public void Reports_which_view_it_read()
    {
        var native = Inspector().Read(@"HKLM\SOFTWARE", null, null, CancellationToken.None);
        var wow = Inspector().Read(@"HKLM\SOFTWARE", null, "32", CancellationToken.None);

        Assert.Equal(RegistryPath.Describe(RegistryPath.NativeView), native.View);
        Assert.Equal("32-bit (WOW6432Node)", wow.View);
    }

    [Fact]
    public void Reads_the_two_views_as_the_different_keys_they_are()
    {
        if (!Environment.Is64BitOperatingSystem)
        {
            return; // One view only; there is nothing to tell apart.
        }

        // The point of the whole view parameter: HKLM\SOFTWARE names two different keys here, and a
        // tool that silently picked one would answer plausibly and wrongly. Compared by subkey set
        // rather than by count, because counts could coincide.
        var native = Inspector(2000).Read(@"HKLM\SOFTWARE", null, "64", CancellationToken.None);
        var wow = Inspector(2000).Read(@"HKLM\SOFTWARE", null, "32", CancellationToken.None);

        Assert.NotEqual(
            native.SubKeyNames.OrderBy(n => n, StringComparer.OrdinalIgnoreCase),
            wow.SubKeyNames.OrderBy(n => n, StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public void Caps_what_it_returns_and_says_it_did()
    {
        var result = Inspector(maxResults: 3).Read(
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", null, null, CancellationToken.None);

        Assert.True(result.Truncated);
        Assert.True(result.Values.Count <= 3);
        Assert.True(result.TotalValues > 3);
    }

    [Fact]
    public void Reads_a_bare_hive_without_disposing_the_base_key_twice()
    {
        // Open() returns the base key itself when there is no subkey, so a second `using` over it
        // would dispose it twice. HKCC is small enough to read whole.
        var result = Inspector().Read("HKCC", null, null, CancellationToken.None);

        Assert.NotEmpty(result.SubKeyNames);

        // And again, to prove the first call left the base key usable rather than disposed.
        var again = Inspector().Read("HKCC", null, null, CancellationToken.None);

        Assert.Equal(result.TotalSubKeys, again.TotalSubKeys);
    }

    [Fact]
    public void Refuses_hklm_sam_before_opening_anything_when_the_server_has_no_read_grant()
    {
        // The scope check is wired into Read itself, ahead of the open: as SYSTEM the open would succeed.
        var ex = Assert.Throws<RegistryQueryException>(
            () => Inspector().Read(@"HKLM\SAM\SAM", null, null, CancellationToken.None));

        Assert.Contains("WINDIAG_ALLOW_ARBITRARY_READ=1", ex.Message);
    }

    [Fact]
    public void Refuses_a_path_that_names_no_hive()
    {
        Assert.Throws<RegistryPathException>(
            () => Inspector().Read(@"SOFTWARE\Microsoft", null, null, CancellationToken.None));
    }
}

public sealed class RegistryRenderingTests
{
    private static RegistryKeyContents Contents(
        IReadOnlyList<RegistryValue> values,
        IReadOnlyList<string>? subKeys = null,
        string view = "64-bit",
        bool truncated = false) =>
        new(@"HKLM\SOFTWARE\Vendor", view, values, subKeys ?? [], values.Count,
            subKeys?.Count ?? 0, truncated);

    [Fact]
    public void Never_glues_a_word_onto_the_end_of_a_view_description()
    {
        // The descriptions are noun phrases of varying shape, and appending "view" to one produced
        // "[32-bit Windows, single view view]" on the live target.
        foreach (var view in new[] { "64-bit", "32-bit (WOW6432Node)", "32-bit Windows, which has only one" })
        {
            var summary = RegistryTools.Render(
                Contents([new RegistryValue("A", "REG_SZ", "x", false, 2)], view: view), null);

            Assert.Contains($"[view: {view}]", summary);
            Assert.DoesNotContain("view view", summary);
        }
    }

    [Fact]
    public void Names_the_view_in_the_first_line()
    {
        var summary = RegistryTools.Render(
            Contents([new RegistryValue("Path", "REG_SZ", @"C:\App", false, 12)]), null);

        Assert.Contains("[view: 64-bit]", summary);
    }

    [Fact]
    public void Points_at_the_other_view_on_every_sixty_four_bit_read()
    {
        // Said always, not only when something looks wrong: the failure mode is finding a plausible
        // key in the wrong view and never questioning it.
        var summary = RegistryTools.Render(
            Contents([new RegistryValue("Path", "REG_SZ", @"C:\App", false, 12)]), null);

        Assert.Contains("WOW6432Node", summary);
    }

    [Fact]
    public void Does_not_suggest_the_other_view_when_already_reading_it()
    {
        var summary = RegistryTools.Render(
            Contents([new RegistryValue("Path", "REG_SZ", @"C:\App", false, 12)],
                view: "32-bit (WOW6432Node)"),
            null);

        Assert.DoesNotContain("pass view='32'", summary);
    }

    [Fact]
    public void Calls_the_unnamed_value_the_default_rather_than_printing_a_blank()
    {
        var summary = RegistryTools.Render(
            Contents([new RegistryValue(string.Empty, "REG_SZ", "Shell", false, 10)]), null);

        Assert.Contains("(Default)", summary);
    }

    [Fact]
    public void Reports_a_truncated_value_with_the_size_actually_stored()
    {
        var summary = RegistryTools.Render(
            Contents([new RegistryValue("Blob", "REG_BINARY", "00 01 02...", true, 1_048_576)]), null);

        Assert.Contains("truncated", summary);
        Assert.Contains("1,048,576 bytes stored", summary);
    }

    [Fact]
    public void Says_a_key_is_empty_rather_than_rendering_nothing()
    {
        var summary = RegistryTools.Render(Contents([]), null);

        Assert.Contains("No values.", summary);
        Assert.Contains("No subkeys.", summary);
    }

    [Fact]
    public void Lists_subkeys_so_a_caller_can_walk_down_without_guessing()
    {
        var summary = RegistryTools.Render(
            Contents([], ["Client", "Server"]), null);

        Assert.Contains("2 subkeys: Client, Server", summary);
    }
}
