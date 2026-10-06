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

public sealed class LogicalDiskWarningTests
{
    private static WinDiag.Mcp.Diagnostics.SystemInfo.LogicalDisk Disk(string type, long free) =>
        new("D:\\", "media", "UDF", 4_000_000_000, free, type);

    [Fact]
    public void A_mounted_iso_is_not_reported_as_running_out_of_space()
    {
        // A read-only volume is always 0% free. Flagging a mounted Windows installer ISO as
        // CRITICALLY LOW trains the reader to ignore the warning on the volume where it matters.
        Assert.False(Disk("CDRom", 0).CanRunOutOfSpace);
    }

    [Fact]
    public void A_real_volume_can_still_run_out_of_space()
    {
        Assert.True(Disk("Fixed", 0).CanRunOutOfSpace);
        Assert.True(Disk("Network", 0).CanRunOutOfSpace);
        Assert.True(Disk("Removable", 0).CanRunOutOfSpace);
    }
}

/// <summary>capture_dump never writes the memory of the processes that hold the machine's credentials.</summary>
/// <remarks>
/// A full dump of lsass, followed by get_file -- which reads the artifact directory with no grant -- used to
/// copy NTLM hashes and Kerberos tickets off the host with nothing but the token.
/// </remarks>
public sealed class CredentialProcessDumpTests
{
    private const string System32 = @"C:\Windows\system32";

    [Theory]
    [InlineData("lsass", @"C:\Windows\System32\lsass.exe")]
    [InlineData("lsaiso", @"C:\Windows\System32\LsaIso.exe")]
    [InlineData("csrss", @"C:\WINDOWS\SYSTEM32\CSRSS.EXE")]
    public void Refuses_a_credential_process_running_from_system32(string name, string imagePath)
    {
        var refusal = MiniDumpWriter.CredentialRefusal(name, 4242, imagePath, System32);

        Assert.NotNull(refusal);
        Assert.Contains(name, refusal, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("PID 4242", refusal);
        Assert.Contains("credentials", refusal);
        Assert.Contains("Nothing was written", refusal);
    }

    [Fact]
    public void Refuses_by_name_when_the_image_path_cannot_be_read()
    {
        // lsass running as a protected process may not even answer a limited query. Not being able to see
        // where it runs from is no reason to assume it is someone else's lsass.
        Assert.NotNull(MiniDumpWriter.CredentialRefusal("lsass", 4242, imagePath: null, System32));
    }

    [Fact]
    public void Dumps_a_process_that_merely_shares_the_name_but_runs_from_elsewhere()
    {
        // Judged by the verified image, not the name: the real lsass only ever runs from System32, and a
        // user's own lsass.exe in a tools folder is theirs to debug.
        Assert.Null(MiniDumpWriter.CredentialRefusal("lsass", 4242, @"C:\Users\dev\tools\lsass.exe", System32));
    }

    [Fact]
    public void Dumps_an_ordinary_system_process()
    {
        Assert.Null(MiniDumpWriter.CredentialRefusal("svchost", 4242, @"C:\Windows\System32\svchost.exe", System32));
        Assert.Null(MiniDumpWriter.CredentialRefusal("notepad", 4242, imagePath: null, System32));
    }

    [Fact]
    public void Refuses_the_real_lsass_on_this_machine_and_writes_nothing()
    {
        // Against the live process, so the check is proven to run before a file is created -- elevation is
        // not needed for the refusal, because it comes before the process is opened for reading.
        var lsass = System.Diagnostics.Process.GetProcessesByName("lsass").Single();
        var artifacts = Path.Combine(Path.GetTempPath(), $"windiag-lsass-{Guid.NewGuid():N}");
        var writer = new MiniDumpWriter(
            WinDiagOptions.FromEnvironment(new Hashtable { ["WINDIAG_ARTIFACT_DIR"] = artifacts }),
            new FakePrivilegeProbe(isElevated: true));

        try
        {
            var ex = Assert.Throws<DumpCaptureException>(
                () => writer.Capture(lsass.Id, DumpKind.Full, CancellationToken.None));

            Assert.Contains("credentials", ex.Message);
            Assert.False(
                Directory.Exists(artifacts) && Directory.EnumerateFiles(artifacts).Any(),
                "a file was written for a refused dump");
        }
        finally
        {
            if (Directory.Exists(artifacts))
            {
                Directory.Delete(artifacts, recursive: true);
            }
        }
    }
}
