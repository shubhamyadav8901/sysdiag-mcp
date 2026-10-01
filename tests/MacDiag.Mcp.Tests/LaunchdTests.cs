using System.Collections;
using System.Text.RegularExpressions;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Services;
using MacDiag.Mcp.Mac.Launchd;
using MacDiag.Mcp.Mac.Parsers;
using static MacDiag.Mcp.Tests.SystemOverviewTests;

namespace MacDiag.Mcp.Tests;

public sealed class LaunchdTests
{
    private static MacDiagOptions Options(string? protectedLabels = null, string? ownLabel = null)
    {
        var environment = new Hashtable();
        if (protectedLabels is not null)
        {
            environment["MACDIAG_PROTECTED_LABELS"] = protectedLabels;
        }

        if (ownLabel is not null)
        {
            environment["MACDIAG_SERVICE_LABEL"] = ownLabel;
        }

        return MacDiagOptions.FromEnvironment(environment);
    }

    [Theory]
    [InlineData("com.example.app", true)]
    [InlineData("org.x-y_z.1", true)]
    [InlineData("", false)]
    [InlineData("com.x\"; rm", false)]
    [InlineData("-k", false)]
    [InlineData(".hidden", false)]
    [InlineData("system/com.x", false)]
    [InlineData("com x", false)]
    [InlineData("com.x\n", false)]
    public void A_label_is_letters_digits_dots_dashes_and_underscores_and_never_starts_like_an_option(string label, bool valid)
    {
        // Review Focus 1.
        if (valid)
        {
            Assert.Equal(label, LaunchdLabel.Check(label, "label"));
        }
        else
        {
            Assert.Throws<ArgumentException>(() => LaunchdLabel.Check(label, "label"));
        }
    }

    [Theory]
    [InlineData("com.apple.WindowServer")]
    [InlineData("com.openssh.sshd")]
    [InlineData("io.tailscale.ipn.macsys")]
    [InlineData("com.paloaltonetworks.gp.pangpsd")]
    [InlineData("COM.APPLE.WindowServer")] // a case variant refuses more, never less
    [InlineData("com.windiag.macdiag")]   // the default label, always
    public void Jobs_that_keep_the_mac_reachable_or_run_this_server_are_refused(string label)
    {
        Assert.NotNull(new LaunchdProtection(Options()).Refusal(label));
    }

    [Fact]
    public void An_ordinary_job_is_allowed_and_configured_labels_protect_exactly_or_by_prefix()
    {
        var protection = new LaunchdProtection(Options("com.example.,org.exact.one"));

        Assert.Null(new LaunchdProtection(Options()).Refusal("com.example.web"));
        Assert.NotNull(protection.Refusal("com.example.web"));
        Assert.NotNull(protection.Refusal("org.exact.one"));
        Assert.Null(protection.Refusal("org.exact.one2"));
    }

    [Fact]
    public void This_servers_own_label_points_to_update_self()
    {
        Assert.Contains("update_self", new LaunchdProtection(Options(ownLabel: "com.corp.diag")).Refusal("com.corp.diag"), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("com.corp.*")]
    [InlineData("com.corp vpn")]
    public void A_protected_label_that_could_never_match_is_a_configuration_error_not_a_silent_gap(string entry)
    {
        Assert.Throws<ConfigurationException>(() => Options(entry));
    }

    [Fact]
    public void A_plist_reads_into_keys_values_arrays_and_nested_dictionaries()
    {
        var plist = PlistXml.Parse(Fixture(Unverified, "plist-sshd.xml"));

        Assert.Equal("com.openssh.sshd", plist.String("Label"));
        Assert.Equal(["/usr/sbin/sshd", "-i"], plist.Strings("ProgramArguments"));
        Assert.True(plist.Bool("RunAtLoad"));
        Assert.False(plist.Dict("KeepAlive")!.Bool("SuccessfulExit"));
        Assert.Equal(3600, plist.Integer("StartInterval"));
        Assert.IsType<PlistOther>(plist["Created"]);
    }

    [Fact]
    public void An_entity_the_document_does_not_declare_is_refused_and_nothing_is_fetched()
    {
        const string hostile =
            "<?xml version=\"1.0\"?><!DOCTYPE plist SYSTEM \"http://example.invalid/x.dtd\"><plist><dict><key>a</key><string>&evil;</string></dict></plist>";

        Assert.Throws<System.Xml.XmlException>(() => PlistXml.Parse(hostile));
    }

    [Fact]
    public async Task Plutil_writes_xml_to_standard_output_and_never_rewrites_the_file()
    {
        // Without -o -, plutil -convert rewrites the file in place: a read becomes a write to a system plist.
        var commands = new FakeCommands((_, _) => FakeCommands.Ok(Fixture(Unverified, "plist-sshd.xml")));

        await Plutil.ReadAsync(commands, "/System/Library/LaunchDaemons/ssh.plist", TimeSpan.FromSeconds(5), CancellationToken.None);

        Assert.Equal("plutil", commands.Calls[0].Program);
        Assert.Equal(["-convert", "xml1", "-o", "-", "/System/Library/LaunchDaemons/ssh.plist"], commands.Calls[0].Arguments);
    }

    [Fact]
    public async Task A_plist_plutil_cannot_read_is_an_error_with_its_message()
    {
        var commands = new FakeCommands((_, _) => new ExternalResult(1, "", "plutil: file does not exist"));

        var ex = await Assert.ThrowsAsync<ServiceQueryException>(() =>
            Plutil.ReadAsync(commands, "/x.plist", TimeSpan.FromSeconds(5), CancellationToken.None));

        Assert.Contains("does not exist", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Plutil_is_run_from_one_place_only()
    {
        var source = ToolSnapshotGuard.RepositoryFile("src", "MacDiag.Mcp");
        var callers = Directory.EnumerateFiles(source, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(f => Regex.IsMatch(File.ReadAllText(f), "\"(/usr/bin/)?plutil\""))
            .Select(Path.GetFileName)
            .ToList();

        Assert.Equal(["Plutil.cs"], callers);
    }
}
