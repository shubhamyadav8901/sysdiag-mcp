using System.Buffers.Binary;
using MacDiag.Mcp.Diagnostics.SelfUpdate;
using MacDiag.Mcp.Mac.Parsers;
using Diag.Mcp.Server.SelfUpdate;

namespace MacDiag.Mcp.Tests;

public sealed class SelfUpdateGuardTests
{
    private const int Arm64 = MachO.CpuTypeArm64;
    private const int X86_64 = MachO.CpuTypeX86_64;

    /// <summary>A thin 64-bit Mach-O header as it sits on disk: little-endian.</summary>
    private static byte[] Thin(int cpuType, uint fileType = 2)
    {
        var header = new byte[32];
        BinaryPrimitives.WriteUInt32BigEndian(header, 0xCFFAEDFE);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(4), cpuType);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(12), fileType);
        return header;
    }

    /// <summary>A universal binary: a big-endian fat header, its slice table, then each slice's thin header.</summary>
    private static byte[] Fat(params (int CpuType, byte[] Slice)[] slices)
    {
        var table = 8 + (20 * slices.Length);
        var file = new byte[table + slices.Sum(s => s.Slice.Length)];
        BinaryPrimitives.WriteUInt32BigEndian(file, 0xCAFEBABE);
        BinaryPrimitives.WriteUInt32BigEndian(file.AsSpan(4), (uint)slices.Length);
        var offset = table;
        for (var i = 0; i < slices.Length; i++)
        {
            BinaryPrimitives.WriteInt32BigEndian(file.AsSpan(8 + (20 * i)), slices[i].CpuType);
            BinaryPrimitives.WriteUInt32BigEndian(file.AsSpan(8 + (20 * i) + 8), (uint)offset);
            BinaryPrimitives.WriteUInt32BigEndian(file.AsSpan(8 + (20 * i) + 12), (uint)slices[i].Slice.Length);
            slices[i].Slice.CopyTo(file, offset);
            offset += slices[i].Slice.Length;
        }

        return file;
    }

    private static MachOVerdict Inspect(byte[] file, bool preferArm64 = true, bool rosetta = true) =>
        MachO.Inspect((offset, count) => file.AsSpan((int)Math.Min(offset, file.Length), (int)Math.Max(0, Math.Min(count, file.Length - offset))).ToArray(),
            preferArm64, () => rosetta);

    [Fact]
    public void A_thin_arm64_executable_is_accepted_as_arm64()
    {
        Assert.Equal(new MachOVerdict(null, Arm64), Inspect(Thin(Arm64)));
    }

    [Theory]
    [InlineData(6u)]  // MH_DYLIB
    [InlineData(8u)]  // MH_BUNDLE
    public void A_library_or_bundle_is_not_an_executable(uint fileType)
    {
        Assert.Contains("not an executable", Inspect(Thin(Arm64, fileType)).Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void A_universal_binary_runs_the_slice_this_mac_prefers()
    {
        var file = Fat((X86_64, Thin(X86_64)), (Arm64, Thin(Arm64)));

        Assert.Equal(Arm64, Inspect(file, preferArm64: true).CpuType);
        Assert.Equal(X86_64, Inspect(file, preferArm64: false).CpuType);
    }

    [Fact]
    public void An_intel_build_on_apple_silicon_needs_rosetta()
    {
        Assert.Equal(X86_64, Inspect(Fat((X86_64, Thin(X86_64))), preferArm64: true, rosetta: true).CpuType);
        Assert.Equal(X86_64, Inspect(Thin(X86_64), preferArm64: true, rosetta: true).CpuType);
        Assert.Contains("Rosetta", Inspect(Thin(X86_64), preferArm64: true, rosetta: false).Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void An_intel_mac_cannot_run_an_arm64_only_build()
    {
        Assert.Contains("cannot run an arm64 build", Inspect(Thin(Arm64), preferArm64: false).Problem, StringComparison.Ordinal);
        Assert.Contains("cannot run an arm64 build", Inspect(Fat((Arm64, Thin(Arm64))), preferArm64: false).Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void A_java_class_file_shares_the_fat_magic_and_is_refused_as_what_it_is()
    {
        // CAFEBABE then a major version of 45 or more, where a fat header would have its slice count.
        var java = new byte[64];
        BinaryPrimitives.WriteUInt32BigEndian(java, 0xCAFEBABE);
        BinaryPrimitives.WriteUInt32BigEndian(java.AsSpan(4), 52);

        Assert.Contains("Java class file", Inspect(java).Problem, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(new byte[] { 0x7F, 0x45, 0x4C, 0x46 }, "Linux executable")]
    [InlineData(new byte[] { 0x4D, 0x5A, 0x90, 0x00 }, "Windows executable")]
    [InlineData(new byte[] { 0xCA, 0xFE, 0xBA, 0xBF }, "64-bit universal")]
    [InlineData(new byte[] { 0x23, 0x21, 0x2F, 0x62 }, "not a Mach-O executable")]
    public void Other_formats_are_named(byte[] magic, string expected)
    {
        var file = new byte[64];
        magic.CopyTo(file, 0);

        Assert.Contains(expected, Inspect(file).Problem, StringComparison.Ordinal);
    }

    [Fact]
    public void A_short_file_or_a_slice_past_the_end_is_refused_not_an_exception()
    {
        Assert.Contains("too short", Inspect(new byte[10]).Problem, StringComparison.Ordinal);

        var cut = Fat((Arm64, Thin(Arm64)))[..40];
        Assert.NotNull(Inspect(cut).Problem);
    }

    [Theory]
    [InlineData(0, "Executable=/x\nIdentifier=a.out\nSignature=adhoc\nTeamIdentifier=not set\n", "AdHoc", null)]
    [InlineData(0, "Executable=/x\nIdentifier=com.example\nTeamIdentifier=ABCDE12345\n", "Signed", "TeamID=ABCDE12345")]
    [InlineData(0, "Executable=/usr/bin/ls\nIdentifier=com.apple.ls\nTeamIdentifier=not set\n", "Signed", null)]
    [InlineData(1, "/x: code object is not signed at all\n", "NotSigned", null)]
    [InlineData(1, "/x: invalid signature (code or signature have been modified)\n", "Unknown", "/x: invalid signature (code or signature have been modified)")]
    public void Codesign_display_gives_one_of_four_verdicts(int exit, string stderr, string verdict, string? detail)
    {
        Assert.Equal((verdict, detail), CodesignDisplay.Verdict(exit, stderr));
    }

    [Fact]
    public void An_arm64_build_must_pass_codesign_verify_and_an_intel_one_need_not()
    {
        var path = Path.Combine(Path.GetTempPath(), $"guard-{Guid.NewGuid():N}");
        try
        {
            File.WriteAllBytes(path, Thin(Arm64));
            var staged = new StagedBuild(path, "AB", 32, "NotSigned", null);
            var failing = new FakeCommands((_, _) => new ExternalResult(1, "", "code object is not signed at all"));

            var ex = Assert.Throws<SelfUpdateRejectedException>(() =>
                new MachOUpdateGuard(failing) { PreferArm64 = true }.RequireAcceptable("/live", staged, CancellationToken.None));
            Assert.Contains("unsigned arm64 binary is killed", ex.Message, StringComparison.Ordinal);
            Assert.Contains("Nothing has been changed", ex.Message, StringComparison.Ordinal);

            File.WriteAllBytes(path, Thin(X86_64));
            new MachOUpdateGuard(failing) { PreferArm64 = false }.RequireAcceptable("/live", staged, CancellationToken.None);
            Assert.Single(failing.Calls);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
