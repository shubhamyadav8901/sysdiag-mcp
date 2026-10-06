using System.Runtime.InteropServices;
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
    public void Marks_a_module_whose_file_was_replaced_and_does_not_call_the_list_clean()
    {
        // Verified, nothing unsigned -- but one module's verdict was never taken, because the file at its
        // path is not the code that is running. "Every module is signed" would be the false comfort the
        // rename-and-replace trick is after.
        var replaced = Module("evil.dll") with { ReplacedOnDisk = true };
        var result = Result([replaced, Module("kernel32.dll", "Valid")]) with { ReplacedCount = 1 };

        var summary = ModuleTools.Render(result, null, true);

        Assert.Contains("evil.dll  C:\\Windows\\System32\\evil.dll  v10.0.19045.1  [REPLACED ON DISK]", summary);
        Assert.Contains("1 module's file on disk is no longer the image that was loaded", summary);
        Assert.DoesNotContain("Every module returned is signed and trusted", summary);
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
    public void Reads_the_same_header_from_leading_bytes_as_from_the_file()
    {
        // The in-memory check hands TryParse the bytes it read out of another process, so the two
        // entry points must agree exactly on the same image.
        var path = typeof(PeImageReaderTests).Assembly.Location;
        var bytes = File.ReadAllBytes(path).AsSpan(0, PeImageReader.HeaderBytes);

        var fromFile = PeImageReader.TryRead(path);
        var fromBytes = PeImageReader.TryParse(bytes);

        Assert.NotNull(fromFile);
        Assert.Equal(fromFile, fromBytes);
        Assert.NotEqual(0u, fromFile!.Value.SizeOfImage);
    }

    [Fact]
    public void A_different_link_stamp_is_a_different_build_but_a_different_image_base_is_not()
    {
        // The loader writes the base an image actually got into the header it maps, so comparing
        // ImageBase would call every relocated module replaced. The link stamp it never touches.
        var original = File.ReadAllBytes(typeof(PeImageReaderTests).Assembly.Location)[..PeImageReader.HeaderBytes];
        var peOffset = BitConverter.ToInt32(original, 0x3C);
        var baseline = PeImageReader.TryParse(original)!.Value;

        var restamped = (byte[])original.Clone();
        restamped[peOffset + 4 + 4] ^= 0x01;

        var rebased = (byte[])original.Clone();
        var magic = BitConverter.ToUInt16(rebased, peOffset + 4 + 20);
        rebased[peOffset + 4 + 20 + (magic == 0x20B ? 24 : 28) + 2] ^= 0x10;

        Assert.False(baseline.IsSameBuildAs(PeImageReader.TryParse(restamped)!.Value));
        Assert.NotEqual(baseline.ImageBase, PeImageReader.TryParse(rebased)!.Value.ImageBase);
        Assert.True(baseline.IsSameBuildAs(PeImageReader.TryParse(rebased)!.Value));
    }

    [Fact]
    public void Refuses_a_pe_offset_that_would_overflow_rather_than_throwing()
    {
        // These bytes can come from another process's memory, outside any try block.
        var bytes = new byte[PeImageReader.HeaderBytes];
        BitConverter.TryWriteBytes(bytes.AsSpan(0x3C), int.MaxValue - 8);

        Assert.Null(PeImageReader.TryParse(bytes));
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

        // Not null: proves the mapped headers were actually read and compared, not skipped.
        Assert.All(result.Modules, m => Assert.False(m.ReplacedOnDisk));
    }

    [Fact]
    public void Flags_a_dll_renamed_away_and_replaced_while_loaded_and_does_not_verify_the_replacement()
    {
        // The hole: NTFS lets a loaded DLL be renamed though not overwritten, and the loader keeps the
        // original path. Rename an unsigned DLL away, put a signed copy at its path, and the module was
        // reported with the copy's version and signature. Done here for real, with system DLLs standing
        // in for both, so the check is against an actual mapping rather than a description of one.
        var directory = Path.Combine(Path.GetTempPath(), $"windiag-modules-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"windiag-probe-{Guid.NewGuid():N}.dll");
        File.Copy(Path.Combine(Environment.SystemDirectory, "version.dll"), path);

        var library = NativeLibrary.Load(path);
        try
        {
            File.Move(path, path + ".loaded");
            File.Copy(Path.Combine(Environment.SystemDirectory, "msimg32.dll"), path);

            var result = Inspector().List(Environment.ProcessId, Path.GetFileName(path), true, CancellationToken.None);

            var module = Assert.Single(result.Modules);
            Assert.True(module.ReplacedOnDisk);
            Assert.Null(module.SignatureVerdict);
            Assert.Null(module.PreferredBase);
            Assert.Equal(1, result.ReplacedCount);
        }
        finally
        {
            NativeLibrary.Free(library);
            Directory.Delete(directory, recursive: true);
        }
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

/// <summary>
/// Whether the file at a module's path is still the loaded image, decided from the two headers alone.
/// </summary>
public sealed class ModuleReplacedOnDiskTests
{
    private static readonly PeImageHeader Loaded = new(0x180000000, DynamicBase: false, PeImageHeader.MachineAmd64,
        TimeDateStamp: 0x5E1F_0001, SizeOfImage: 0x2_0000, CheckSum: 0x1_2345);

    /// <summary>What the loader leaves in the mapped header after moving the image: only ImageBase.</summary>
    private static readonly PeImageHeader SameFileOnDisk = Loaded with { ImageBase = 0x10000000 };

    private static readonly PeImageHeader OtherFileOnDisk = SameFileOnDisk with { TimeDateStamp = 0x6000_0002 };

    [Fact]
    public void A_file_matching_the_loaded_header_is_not_replaced_even_though_the_image_was_moved()
    {
        Assert.False(WindowsModuleInspector.ReplacedOnDisk(Loaded, SameFileOnDisk, fileExists: true));
    }

    [Fact]
    public void A_file_with_a_different_build_header_is_replaced()
    {
        Assert.True(WindowsModuleInspector.ReplacedOnDisk(Loaded, OtherFileOnDisk, fileExists: true));
    }

    [Fact]
    public void A_file_that_is_gone_is_replaced()
    {
        Assert.True(WindowsModuleInspector.ReplacedOnDisk(Loaded, null, fileExists: false));
    }

    [Fact]
    public void Says_unknown_rather_than_no_when_either_header_could_not_be_read()
    {
        // An unreadable mapping or an access-denied file is not evidence that nothing changed.
        Assert.Null(WindowsModuleInspector.ReplacedOnDisk(null, SameFileOnDisk, fileExists: true));
        Assert.Null(WindowsModuleInspector.ReplacedOnDisk(Loaded, null, fileExists: true));
    }

    [Fact]
    public void Takes_no_relocation_verdict_from_a_header_that_belongs_to_another_file()
    {
        // The replacement here was built for a fixed base and the loaded image is not at it: read naively
        // that is a base collision, which would be a finding about a file that is not even loaded.
        var module = WindowsModuleInspector.Describe(
            "evil.dll", @"C:\App\evil.dll", 0x180000000, 4096, "10.0.1", "Microsoft Corporation",
            loaded: Loaded, onDisk: OtherFileOnDisk, fileExists: true);

        Assert.True(module.ReplacedOnDisk);
        Assert.Null(module.PreferredBase);
        Assert.Null(module.Relocated);
        Assert.False(module.BaseCollision);
    }

    [Fact]
    public void Still_reads_the_preferred_base_from_the_file_when_it_matches()
    {
        var module = WindowsModuleInspector.Describe(
            "app.dll", @"C:\App\app.dll", 0x180000000, 4096, null, null,
            loaded: Loaded, onDisk: SameFileOnDisk, fileExists: true);

        Assert.False(module.ReplacedOnDisk);
        Assert.Equal("0x10000000", module.PreferredBase);
        Assert.True(module.BaseCollision);
    }

    [Fact]
    public void Does_not_verify_the_file_that_replaced_a_loaded_module()
    {
        // The verdict would be the replacement's -- signed, in the attack -- and the module would then
        // drop out of the unsigned count the tool exists to produce.
        var signatures = new RecordingSignatureInspector();
        var inspector = new WindowsModuleInspector(signatures, WinDiagOptions.FromEnvironment(new System.Collections.Hashtable()));

        var replaced = new LoadedModule("evil.dll", @"C:\App\evil.dll", "0x1", 1, null, null, null, null, ReplacedOnDisk: true);
        var intact = new LoadedModule("app.dll", @"C:\App\app.dll", "0x2", 1, null, null, null, null, ReplacedOnDisk: false);

        var verified = inspector.Verify([replaced, intact], CancellationToken.None);

        Assert.Equal([@"C:\App\app.dll"], signatures.Asked);
        Assert.Null(verified.Single(m => m.Name == "evil.dll").SignatureVerdict);
        Assert.Equal("Valid", verified.Single(m => m.Name == "app.dll").SignatureVerdict);
    }

    /// <summary>Calls every file it is asked about validly signed, and remembers what it was asked.</summary>
    private sealed class RecordingSignatureInspector : ISignatureInspector
    {
        public List<string> Asked { get; } = [];

        public SignatureQueryResult Inspect(IReadOnlyList<string> paths, CancellationToken cancellationToken)
        {
            Asked.AddRange(paths);

            return new SignatureQueryResult(
                paths.Select(p => new FileSignature(
                    p, SignatureVerdict.Valid, "Signature is present and trusted.", false, "Microsoft Windows",
                    null, null, null, null, null, null, 1, DateTimeOffset.UnixEpoch, "00")).ToList(),
                []);
        }

        public FileSignature InspectHeld(string path, CancellationToken cancellationToken) =>
            throw new NotSupportedException("module verification never holds a file");
    }
}
