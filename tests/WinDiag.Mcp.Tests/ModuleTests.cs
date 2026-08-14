using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.Modules;
using WinDiag.Mcp.Diagnostics.Signatures;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

public sealed class ModuleRenderingTests
{
    private static LoadedModule Module(string name, string? verdict = null, bool collision = false) =>
        new(name, $@"C:\Windows\System32\{name}", "0x7FF800000000", 1_234_567, "10.0.19045.1", "Microsoft",
            verdict, null, PreferredBase: "0x10000000", Relocated: true, BaseCollision: collision);

    private static ModuleListResult Result(
        IReadOnlyList<LoadedModule> modules,
        string? limitation = null,
        bool truncated = false,
        int unsigned = 0,
        int collisions = 0) =>
        new(42, "app", modules, modules.Count, truncated, unsigned, limitation, collisions);

    [Fact]
    public void Leads_with_a_partial_read_because_a_short_list_looks_like_a_small_process()
    {
        var summary = ModuleTools.Render(
            Result([Module("kernel32.dll")], limitation: "Only part of the module list could be read."),
            null, false);

        Assert.StartsWith("WARNING", summary);
    }

    [Fact]
    public void Says_signatures_were_not_checked_rather_than_implying_they_were_clean()
    {
        var summary = ModuleTools.Render(Result([Module("kernel32.dll")]), null, verified: false);

        Assert.Contains("Signatures were not checked", summary);
    }

    [Fact]
    public void Points_at_the_unsigned_modules_when_verification_ran()
    {
        var summary = ModuleTools.Render(
            Result([Module("evil.dll", "Unsigned")], unsigned: 1), null, verified: true);

        Assert.Contains("[UNSIGNED]", summary);
        Assert.Contains("1 of the modules returned is unsigned", summary);
        Assert.Contains("worth looking at first", summary);
    }

    [Fact]
    public void Counts_several_unsigned_modules_without_mangling_the_sentence()
    {
        var summary = ModuleTools.Render(
            Result([Module("a.dll", "Unsigned"), Module("b.dll", "Untrusted")], unsigned: 2),
            null, verified: true);

        Assert.Contains("2 of the modules returned are unsigned", summary);
    }

    [Fact]
    public void Confirms_a_clean_result_explicitly()
    {
        var summary = ModuleTools.Render(Result([Module("kernel32.dll", "Valid")]), null, verified: true);

        Assert.Contains("signed and trusted", summary);
        Assert.DoesNotContain("[VALID]", summary);
    }

    [Fact]
    public void Stays_quiet_about_relocation_when_it_is_only_aslr()
    {
        // Every module in this result has Relocated: true, because on any modern Windows they all are.
        // Flagging that would bury the collisions in noise, which is the whole reason the two are
        // separate fields.
        var summary = ModuleTools.Render(Result([Module("kernel32.dll"), Module("user32.dll")]), null, false);

        Assert.DoesNotContain("REBASED", summary);
        Assert.DoesNotContain("occupied that range", summary);
    }

    [Fact]
    public void Calls_out_a_module_that_was_moved_despite_asking_not_to_be()
    {
        var summary = ModuleTools.Render(
            Result([Module("legacy.dll", collision: true)], collisions: 1), null, false);

        Assert.Contains("[REBASED from 0x10000000]", summary);
        Assert.Contains("1 module was", summary);
        Assert.Contains("already occupied that range", summary);
    }

    [Fact]
    public void Reports_an_empty_filter_match_as_a_real_answer()
    {
        // Distinct from an enumeration that failed: that one throws rather than reaching the renderer,
        // precisely so "0 modules" can only ever mean "the filter matched nothing".
        var summary = ModuleTools.Render(Result([]), "nosuchmodule", false);

        Assert.Contains("0 modules in app", summary);
        Assert.Contains("matching 'nosuchmodule'", summary);
        Assert.DoesNotContain("WARNING", summary);
    }
}

/// <summary>
/// The PE header read behind the relocation fields.
/// </summary>
/// <remarks>
/// Fixture-free on purpose: every Windows machine ships images of both bitnesses, and asserting
/// against the real ones is what catches an offset that is right for PE32 and wrong for PE32+.
/// </remarks>
public sealed class PeImageReaderTests
{
    [Fact]
    public void Reads_the_preferred_base_of_a_real_system_image()
    {
        var kernel32 = Path.Combine(Environment.SystemDirectory, "kernel32.dll");

        var header = PeImageReader.TryRead(kernel32);

        Assert.NotNull(header);
        Assert.NotEqual(0UL, header!.Value.ImageBase);

        // Everything Microsoft ships has been built /DYNAMICBASE for over a decade. If this ever fails,
        // the flag offset is wrong rather than the assumption.
        Assert.True(header.Value.DynamicBase);
    }

    [Fact]
    public void Reads_this_test_assembly_too()
    {
        var header = PeImageReader.TryRead(typeof(PeImageReaderTests).Assembly.Location);

        Assert.NotNull(header);
        Assert.NotEqual(0UL, header!.Value.ImageBase);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Returns_null_rather_than_throwing_on_a_path_it_cannot_use(string path)
    {
        Assert.Null(PeImageReader.TryRead(path));
    }

    [Fact]
    public void Returns_null_for_a_file_that_is_not_a_pe_image()
    {
        // A module whose file has been replaced or truncated under the running process is normal; it
        // must cost that one module's relocation data and nothing else.
        var temp = Path.Combine(Path.GetTempPath(), $"windiag-notpe-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(temp, [.. Enumerable.Repeat((byte)0x41, 2048)]);

        try
        {
            Assert.Null(PeImageReader.TryRead(temp));
        }
        finally
        {
            File.Delete(temp);
        }
    }

    [Fact]
    public void Returns_null_for_a_file_too_short_to_have_a_header()
    {
        var temp = Path.Combine(Path.GetTempPath(), $"windiag-short-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(temp, [0x4D, 0x5A]);

        try
        {
            Assert.Null(PeImageReader.TryRead(temp));
        }
        finally
        {
            File.Delete(temp);
        }
    }

    [Fact]
    public void Returns_null_for_a_path_that_does_not_exist()
    {
        Assert.Null(PeImageReader.TryRead(Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.dll")));
    }

    [Fact]
    public void Sees_an_image_that_did_not_opt_into_aslr()
    {
        // Everything on a modern Windows install is /DYNAMICBASE, so the positive assertion above would
        // pass just as happily if the offset were wrong and the read were picking up some other
        // always-nonzero field. This clears exactly that bit in a copy of a real image and requires the
        // reader to notice -- and requires ImageBase to come back unchanged, which is what proves the
        // byte that moved was the one intended.
        var source = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
        var before = PeImageReader.TryRead(source);
        Assert.NotNull(before);
        Assert.True(before!.Value.DynamicBase);

        var copy = Path.Combine(Path.GetTempPath(), $"windiag-noaslr-{Guid.NewGuid():N}.dll");
        File.Copy(source, copy, overwrite: true);

        try
        {
            var bytes = File.ReadAllBytes(copy);
            var peOffset = BitConverter.ToInt32(bytes, 0x3C);
            var dllCharacteristics = peOffset + 4 + 20 + 70;

            var flags = BitConverter.ToUInt16(bytes, dllCharacteristics);
            BitConverter.TryWriteBytes(bytes.AsSpan(dllCharacteristics), (ushort)(flags & ~0x0040));
            File.WriteAllBytes(copy, bytes);

            var after = PeImageReader.TryRead(copy);

            Assert.NotNull(after);
            Assert.False(after!.Value.DynamicBase);
            Assert.Equal(before.Value.ImageBase, after.Value.ImageBase);
        }
        finally
        {
            File.Delete(copy);
        }
    }
}

/// <summary>
/// What the inspector does against real processes on this machine.
/// </summary>
public sealed class ModuleInspectorTests
{
    private static WindowsModuleInspector Inspector() =>
        new(new WinTrustSignatureInspector(),
            WinDiagOptions.FromEnvironment(new System.Collections.Hashtable()));

    [Fact]
    public void Lists_its_own_modules_with_a_preferred_base_for_each()
    {
        var result = Inspector().List(Environment.ProcessId, null, false, CancellationToken.None);

        Assert.NotEmpty(result.Modules);
        Assert.Null(result.Limitation);

        // The relocation fields are the point: a base address with nothing to compare it against is a
        // number the caller cannot act on.
        Assert.All(result.Modules, m => Assert.NotNull(m.PreferredBase));
        Assert.All(result.Modules, m => Assert.NotNull(m.Relocated));
    }

    [Fact]
    public void Refuses_a_pid_that_is_not_running_rather_than_returning_nothing()
    {
        var ex = Assert.Throws<ModuleQueryException>(
            () => Inspector().List(-1, null, false, CancellationToken.None));

        Assert.Contains("process_list", ex.Message);
    }

    [Fact]
    public void Names_the_bitness_fix_when_nothing_at_all_can_be_read()
    {
        // PID 4 is System: kernel-only, so module enumeration fails outright. An empty list with a
        // warning attached would still headline as "0 modules"; a refusal that names the cause will not
        // be misread. This is the same path a win-x86 server hits against every 64-bit process.
        var ex = Assert.Throws<ModuleQueryException>(
            () => Inspector().List(4, null, false, CancellationToken.None));

        Assert.Contains("No modules could be read", ex.Message);
        Assert.DoesNotContain("Only part", ex.Message);
    }
}
