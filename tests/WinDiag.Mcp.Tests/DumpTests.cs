using System.Collections;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.Dumps;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

public sealed class DumpKindParsingTests
{
    [Theory]
    [InlineData("mini")]
    [InlineData("MINI")]
    [InlineData(" minidump ")]
    [InlineData("small")]
    [InlineData("")]
    public void Defaults_to_the_cheap_dump(string kind)
    {
        Assert.Equal(DumpKind.Mini, DumpTools.ParseKind(kind));
    }

    [Theory]
    [InlineData("full")]
    [InlineData("Complete")]
    public void Recognises_the_expensive_dump(string kind)
    {
        Assert.Equal(DumpKind.Full, DumpTools.ParseKind(kind));
    }

    [Fact]
    public void Rejects_an_unknown_kind_rather_than_guessing()
    {
        // Guessing here picks between a 2 MB file and a 4 GB one.
        var ex = Assert.Throws<ArgumentException>(() => DumpTools.ParseKind("everything"));

        Assert.Contains("'mini' or 'full'", ex.Message);
    }
}

public sealed class AdminSharePathTests
{
    [Fact]
    public void Rewrites_a_local_path_for_another_machine_to_open()
    {
        // This is what saves copying gigabytes: cdb opens the UNC form directly.
        var unc = MiniDumpWriter.ToAdminShare(@"C:\temp\windiag\app_123.dmp");

        Assert.Equal($@"\\{Environment.MachineName}\C$\temp\windiag\app_123.dmp", unc);
    }

    [Fact]
    public void Handles_a_drive_other_than_c()
    {
        Assert.Equal(
            $@"\\{Environment.MachineName}\D$\dumps\x.dmp",
            MiniDumpWriter.ToAdminShare(@"D:\dumps\x.dmp"));
    }

    [Theory]
    [InlineData(@"\\server\share\x.dmp")]
    [InlineData(@"\\?\Volume{11111111-1111-1111-1111-111111111111}\x.dmp")]
    public void Returns_nothing_for_a_path_with_no_drive_letter(string path)
    {
        // Inventing a UNC path for these would produce one that does not resolve, which is worse than
        // admitting there isn't one.
        Assert.Null(MiniDumpWriter.ToAdminShare(path));
    }
}

public sealed class DumpRenderingTests
{
    private static DumpResult Dump(
        string? unc = @"\\HOST\C$\temp\app_42.dmp",
        DumpKind kind = DumpKind.Mini,
        bool elevated = true,
        bool wow64 = false) =>
        new(@"C:\temp\app_42.dmp", unc, 2_500_000, 42, "app", kind, elevated, wow64);

    [Fact]
    public void Points_at_mcp_windbg_with_the_path_it_can_open()
    {
        var summary = DumpTools.Render(Dump());

        Assert.Contains("app", summary);
        Assert.Contains("PID 42", summary);
        Assert.Contains(@"C:\temp\app_42.dmp", summary);
        Assert.Contains(@"\\HOST\C$\temp\app_42.dmp", summary);
        Assert.Contains("open_windbg_dump", summary);
    }

    [Fact]
    public void Says_the_file_must_be_copied_when_there_is_no_share_path()
    {
        var summary = DumpTools.Render(Dump(unc: null));

        Assert.DoesNotContain("open_windbg_dump", summary);
        Assert.Contains("Copy the file", summary);
    }

    [Fact]
    public void Warns_that_an_unelevated_success_does_not_generalise()
    {
        // Dumping your own process works unelevated; dumping anything interesting often does not.
        var summary = DumpTools.Render(Dump(elevated: false));

        Assert.Contains("not elevated", summary);
    }

    [Fact]
    public void Reports_size_in_human_units()
    {
        Assert.Contains("2.4 MB", DumpTools.Render(Dump()));
    }

    [Fact]
    public void Tells_the_analyst_how_to_read_a_32_bit_dump()
    {
        // A 64-bit dumper writing a 32-bit target produces stacks full of WOW64 thunk frames. Someone
        // who does not know that concludes the capture is broken.
        var summary = DumpTools.Render(Dump(wow64: true));

        Assert.Contains("32-bit process on 64-bit Windows", summary);
        Assert.Contains("!wow64exts.sw", summary);
    }

    [Fact]
    public void Stays_quiet_about_bitness_for_a_64_bit_target()
    {
        Assert.DoesNotContain("wow64", DumpTools.Render(Dump()), StringComparison.OrdinalIgnoreCase);
    }
}

public sealed class ArtifactDirectoryTests
{
    [Fact]
    public void Defaults_under_the_temp_directory()
    {
        var options = WinDiagOptions.FromEnvironment(new Hashtable());

        Assert.Equal(WinDiagOptions.DefaultArtifactDirectory, options.ArtifactDirectory);
        Assert.Contains("windiag", options.ArtifactDirectory);
    }

    [Fact]
    public void Resolves_a_relative_path_to_a_full_one()
    {
        // A relative directory would otherwise land wherever the process was started from, which on a
        // target machine is unpredictable and makes the returned path useless to the caller.
        var env = new Hashtable { ["WINDIAG_ARTIFACT_DIR"] = "dumps" };

        var resolved = WinDiagOptions.FromEnvironment(env).ArtifactDirectory;

        Assert.True(Path.IsPathFullyQualified(resolved), resolved);
    }

    [Fact]
    public void Honours_an_absolute_override()
    {
        var env = new Hashtable { ["WINDIAG_ARTIFACT_DIR"] = @"D:\captures" };

        Assert.Equal(@"D:\captures", WinDiagOptions.FromEnvironment(env).ArtifactDirectory);
    }

    [Fact]
    public void Appears_in_the_startup_summary()
    {
        Assert.Contains("artifactDir=", WinDiagOptions.FromEnvironment(new Hashtable()).Describe());
    }

    [Fact]
    public void Rejects_a_malformed_path_at_startup_rather_than_mid_capture()
    {
        var env = new Hashtable { ["WINDIAG_ARTIFACT_DIR"] = "C:\\bad\0path" };

        Assert.Throws<ConfigurationException>(() => WinDiagOptions.FromEnvironment(env));
    }
}
