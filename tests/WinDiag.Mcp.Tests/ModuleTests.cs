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
    public void Marks_a_module_whose_listed_path_was_replaced_and_says_where_its_loaded_file_is()
    {
        // The verdict beside it is the loaded file's own -- unsigned, in the rename-and-replace trick --
        // so the marker has to say the listed path is the thing that is stale, and point at the file the
        // version and verdict were actually read from.
        var replaced = Module("evil.dll", "Unsigned") with
        {
            ReplacedOnDisk = true,
            ImageFilePath = @"C:\Windows\System32\evil.dll.old"
        };
        var result = Result([replaced, Module("kernel32.dll", "Valid")], unsigned: 1) with { ReplacedCount = 1 };

        var summary = ModuleTools.Render(result, null, true);

        Assert.Contains(
            @"evil.dll  C:\Windows\System32\evil.dll  v10.0.19045.1  [REPLACED ON DISK]  loaded file now at " +
            @"C:\Windows\System32\evil.dll.old  [UNSIGNED]", summary);
        Assert.Contains("1 module's listed path no longer holds the image that was loaded", summary);
        Assert.Contains("1 of the modules returned is unsigned", summary);
    }

    [Fact]
    public void Never_calls_the_list_clean_while_a_module_went_unverified()
    {
        // Nothing unsigned, but one module's loaded file was never identified, so it was never checked.
        // "Every module is signed" would be exactly the false comfort a hidden module is after.
        var unknown = Module("hidden.dll", LoadedModule.NotVerified) with
        {
            FileVersion = null,
            ImageFileUnknownReason = "the kernel did not name the file mapped at 0x1 (error 5: Access is denied.)"
        };
        var result = Result([unknown, Module("kernel32.dll", "Valid")]) with
        {
            UnidentifiedCount = 1,
            NotVerifiedCount = 1
        };

        var summary = ModuleTools.Render(result, null, true);

        Assert.Contains(@"hidden.dll  C:\Windows\System32\hidden.dll  [FILE NOT IDENTIFIED]  [NOT VERIFIED]", summary);
        Assert.Contains("1 of those returned could not be checked", summary);
        Assert.Contains("unchecked, not clean", summary);
        Assert.Contains("1 module's loaded file could not be identified", summary);
        Assert.Contains("for hidden.dll, the kernel did not name the file", summary);
        Assert.DoesNotContain("Every module returned is signed and trusted", summary);
    }

    [Fact]
    public void Never_calls_the_list_clean_while_a_verification_did_not_finish()
    {
        // WinVerifyTrust's own "could not tell" is not a signature either.
        var summary = ModuleTools.Render(
            Result([Module("odd.dll", "Unknown"), Module("kernel32.dll", "Valid")]), null, verified: true);

        Assert.Contains("[UNKNOWN]", summary);
        Assert.DoesNotContain("Every module returned is signed and trusted", summary);
    }

    [Fact]
    public void Marks_an_unidentified_module_even_when_signatures_were_not_asked_for()
    {
        // Its version is missing on purpose; unmarked, that reads as a DLL without a version resource.
        var unknown = Module("hidden.dll") with { FileVersion = null, ImageFileUnknownReason = "no" };
        var summary = ModuleTools.Render(Result([unknown]) with { UnidentifiedCount = 1 }, null, verified: false);

        Assert.Contains("hidden.dll  C:\\Windows\\System32\\hidden.dll  [FILE NOT IDENTIFIED]", summary);
        Assert.Contains("1 module's loaded file could not be identified", summary);
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
    public void Reads_the_same_header_through_a_held_stream_as_by_path()
    {
        // process_modules reads through the handle it identified the file with, never the path, so the
        // two entry points must agree exactly on the same image.
        var path = typeof(PeImageReaderTests).Assembly.Location;
        using var held = new MemoryStream(File.ReadAllBytes(path));
        held.Seek(123, SeekOrigin.Begin);

        var fromFile = PeImageReader.TryRead(path);
        var fromStream = PeImageReader.TryRead(held);

        Assert.NotNull(fromFile);
        Assert.Equal(fromFile, fromStream);
    }

    /// <summary>
    /// A minimal PE32+ image whose NT headers start at <paramref name="peOffset"/>: just the fields the
    /// reader and the loader look at, so a test can put them anywhere the loader would accept.
    /// </summary>
    internal static byte[] SyntheticImage(int peOffset, ulong imageBase = 0x1_8000_0000, bool dynamicBase = true)
    {
        var bytes = new byte[peOffset + 0x200];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        BitConverter.TryWriteBytes(bytes.AsSpan(0x3C), peOffset);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(peOffset));
        BitConverter.TryWriteBytes(bytes.AsSpan(peOffset + 4), PeImageHeader.MachineAmd64);
        var optional = peOffset + 4 + 20;
        BitConverter.TryWriteBytes(bytes.AsSpan(optional), (ushort)0x20B);
        BitConverter.TryWriteBytes(bytes.AsSpan(optional + 24), imageBase);
        BitConverter.TryWriteBytes(bytes.AsSpan(optional + 70), (ushort)(dynamicBase ? 0x40 : 0));
        return bytes;
    }

    [Fact]
    public void Reads_nt_headers_the_loader_would_find_past_the_first_kilobyte()
    {
        // The loader takes e_lfanew anywhere below 256 MB that the file actually reaches. Reading a fixed
        // 1 KB and refusing whatever lay past it called such an image "not a PE" -- an image that loads
        // and runs, and one an attacker could build on purpose to make every check of it come back
        // unknown.
        var temp = Path.Combine(Path.GetTempPath(), $"windiag-farpe-{Guid.NewGuid():N}.dll");
        File.WriteAllBytes(temp, SyntheticImage(peOffset: 0x1400, imageBase: 0x1_8000_0000, dynamicBase: false));

        try
        {
            var header = PeImageReader.TryRead(temp);

            Assert.NotNull(header);
            Assert.Equal(0x1_8000_0000UL, header!.Value.ImageBase);
            Assert.Equal(PeImageHeader.MachineAmd64, header.Value.Machine);
            Assert.False(header.Value.DynamicBase);
        }
        finally
        {
            File.Delete(temp);
        }
    }

    [Fact]
    public void Refuses_an_e_lfanew_the_loader_refuses_and_one_past_the_end_of_the_file()
    {
        // RtlImageNtHeaderEx refuses 256 MB and over outright; anything shorter than the headers it
        // points at is not an image either. Neither may throw: the bytes are the target's, not ours.
        var tooFar = SyntheticImage(peOffset: 0x80);
        BitConverter.TryWriteBytes(tooFar.AsSpan(0x3C), 0x1000_0000);
        var pastTheEnd = SyntheticImage(peOffset: 0x80)[..0x90];
        var negative = SyntheticImage(peOffset: 0x80);
        BitConverter.TryWriteBytes(negative.AsSpan(0x3C), -4);
        var nearIntMax = SyntheticImage(peOffset: 0x80);
        BitConverter.TryWriteBytes(nearIntMax.AsSpan(0x3C), int.MaxValue - 8);
        var noMz = SyntheticImage(peOffset: 0x80);
        noMz[0] = (byte)'X';

        foreach (var bytes in new[] { tooFar, pastTheEnd, negative, nearIntMax, noMz })
        {
            var temp = Path.Combine(Path.GetTempPath(), $"windiag-badpe-{Guid.NewGuid():N}.dll");
            File.WriteAllBytes(temp, bytes);
            try
            {
                Assert.Null(PeImageReader.TryRead(temp));
            }
            finally
            {
                File.Delete(temp);
            }
        }
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
/// What the inspector does against real processes and real files on this machine. Windows only: CI's
/// windows-latest job runs these, and they are what proves the kernel calls behave as the identity
/// argument in <see cref="ModuleImageIdentity.WhyNotTheMappedFile"/> needs them to.
/// </summary>
public sealed class ModuleInspectorTests
{
    private static WindowsModuleInspector Inspector() =>
        new(new WinTrustSignatureInspector(),
            WinDiagOptions.FromEnvironment(new System.Collections.Hashtable()));

    [Fact]
    public void Lists_its_own_modules_each_identified_by_its_mapped_file_with_a_preferred_base()
    {
        var result = Inspector().List(Environment.ProcessId, null, false, CancellationToken.None);

        Assert.NotEmpty(result.Modules);
        Assert.Null(result.Limitation);

        // A module may go unidentified only because someone other than SYSTEM, Administrators and
        // TrustedInstaller can change a directory on its path -- this test's own output directory, under
        // the runner's account, may well be one. Never for the mechanics: were the kernel's name for a
        // mapping and the name a file opened under it reports spelled differently, every module everywhere
        // would be [FILE NOT IDENTIFIED] -- safe, and useless.
        Assert.All(result.Modules, m =>
        {
            if (m.ImageFileUnknownReason is { } reason)
            {
                Assert.EndsWith(ModuleImageIdentity.OnlyAdminPathsTrusted, reason);
            }
        });

        // System32 is TrustedInstaller's, so its modules prove the whole chain works: named, opened, held,
        // its directories judged, and the file read.
        var system = result.Modules
            .Where(m => m.Path.StartsWith(Environment.SystemDirectory + @"\", StringComparison.OrdinalIgnoreCase))
            .ToList();
        Assert.Contains(system, m => m.Name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase));
        // The reason in the message: on a runner image whose C:\ grants more than stock Windows, it names
        // the directory and the entry that cost every module its identity.
        Assert.All(system, m => Assert.True(m.ImageFileUnknownReason is null, $"{m.Path}: {m.ImageFileUnknownReason}"));

        // The relocation fields are the point: a base address with nothing to compare it against is a
        // number the caller cannot act on.
        Assert.All(system, m => Assert.NotNull(m.PreferredBase));
        Assert.All(system, m => Assert.NotNull(m.Relocated));

        // Not null: the listed path was opened and compared by file ID, not skipped.
        Assert.All(system, m => Assert.False(m.ReplacedOnDisk));
    }

    [Fact]
    public void Never_verifies_the_file_put_at_a_loaded_dlls_path_after_it_was_renamed_away_in_a_users_directory()
    {
        // The hole, both halves of it. Rename an unsigned DLL away while it is loaded and put a signed one
        // at its path: the signed one was verified in its place. Comparing PE headers caught a careless
        // swap, but not this one -- the loaded DLL is a byte-for-byte copy of the signed one except in its
        // DOS stub, so stamp, size, checksum and machine all match, and only the signature tells them
        // apart. The kernel's name for the mapping does follow this rename; but in %TEMP% the user could
        // as well have renamed the directory, which that name does not follow (the test below), and the
        // two look the same from here. So a module there gets no verdict at all, naming the directory.
        var directory = Path.Combine(Path.GetTempPath(), $"windiag-modules-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"windiag-probe-{Guid.NewGuid():N}.dll");
        var signed = Path.Combine(Environment.SystemDirectory, "version.dll");

        // One byte of "This program cannot be run in DOS mode": inside the Authenticode hash, outside
        // anything the loader reads. Embedded signature or catalog entry, neither matches it any more.
        var unsigned = File.ReadAllBytes(signed);
        var stub = unsigned.AsSpan(0, 0x80).IndexOf("program"u8);
        Assert.True(stub > 0, "version.dll has no DOS stub text to alter");
        unsigned[stub] ^= 0x20;
        File.WriteAllBytes(path, unsigned);

        var library = NativeLibrary.Load(path);
        try
        {
            File.Move(path, path + ".loaded");
            File.Copy(signed, path);

            // The premise the policy's one exemption rests on: a user who may rename what is in the DLL's
            // own directory is let through, because the kernel's name for the mapping follows a rename of
            // the file itself. Were it not to, that exemption would be the hole all over again.
            Assert.EndsWith(".loaded", MappedFileNameOf(library), StringComparison.OrdinalIgnoreCase);

            var result = Inspector().List(Environment.ProcessId, Path.GetFileName(path), true, CancellationToken.None);

            var module = Assert.Single(result.Modules);
            Assert.Equal(LoadedModule.NotVerified, module.SignatureVerdict);
            Assert.Null(module.Signer);
            Assert.Null(module.FileVersion);
            Assert.Null(module.PreferredBase);

            // The reason names the first directory on the DLL's path that a non-admin can change. The
            // kernel's name should keep the spelling the DLL was loaded under -- a runner's RUNNER~1 short
            // name included -- but either spelling of this test's path is accepted.
            var reason = Assert.IsType<string>(module.ImageFileUnknownReason);
            Assert.EndsWith(ModuleImageIdentity.OnlyAdminPathsTrusted, reason);
            Assert.Contains(ModuleImageIdentity.DirectoriesAbove(path).Concat(ModuleImageIdentity.DirectoriesAbove(LongPathOf(path))),
                d => reason.StartsWith(d + " ", StringComparison.OrdinalIgnoreCase));

            Assert.Equal(1, result.UnidentifiedCount);
            Assert.Equal(1, result.NotVerifiedCount);
            Assert.Equal(0, result.UnsignedCount);
        }
        finally
        {
            NativeLibrary.Free(library);
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Never_verifies_the_file_put_at_a_loaded_dlls_path_after_its_directory_was_renamed_away()
    {
        // The same swap one level up: rename the loaded DLL's directory rather than the DLL, and rebuild
        // the old path around a signed copy. The identity argument needs the kernel's name for a mapping to
        // follow a rename of any directory above the file, not only of the file itself. If it did not, the
        // mapping would still read as the old path, the open there would find the signed copy, and that
        // copy's verdict would be reported for the code running. Identified at its new place, or not
        // identified at all, are both honest; Valid is the hole.
        var parent = Path.Combine(Path.GetTempPath(), $"windiag-moddir-{Guid.NewGuid():N}");
        var directory = Path.Combine(parent, "lib");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"windiag-probe-{Guid.NewGuid():N}.dll");
        var signed = Path.Combine(Environment.SystemDirectory, "version.dll");

        var unsigned = File.ReadAllBytes(signed);
        var stub = unsigned.AsSpan(0, 0x80).IndexOf("program"u8);
        Assert.True(stub > 0, "version.dll has no DOS stub text to alter");
        unsigned[stub] ^= 0x20;
        File.WriteAllBytes(path, unsigned);

        var library = NativeLibrary.Load(path);
        try
        {
            try
            {
                Directory.Move(directory, directory + ".moved");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A mapped image pinning its directory would make the swap impossible, which is safe too.
                return;
            }

            Directory.CreateDirectory(directory);
            File.Copy(signed, path);

            var result = Inspector().List(Environment.ProcessId, Path.GetFileName(path), true, CancellationToken.None);

            var module = Assert.Single(result.Modules);
            Assert.NotEqual("Valid", module.SignatureVerdict);
            if (module.ImageFileUnknownReason is null)
            {
                Assert.True(module.ReplacedOnDisk);
                Assert.Contains(".moved", module.ImageFilePath, StringComparison.OrdinalIgnoreCase);
                Assert.Contains(module.SignatureVerdict, new[] { "Unsigned", "Untrusted" });
            }
        }
        finally
        {
            NativeLibrary.Free(library);
            Directory.Delete(parent, recursive: true);
        }
    }

    [Fact]
    public void A_file_held_as_a_module_file_is_held_cannot_be_renamed_and_neither_can_its_directory()
    {
        // The identity argument rests on this: once the image's file is held, shared for reading only,
        // the name it was opened under cannot move -- not by renaming it, and not by renaming a directory
        // above it and putting another tree in its place.
        var parent = Path.Combine(Path.GetTempPath(), $"windiag-hold-{Guid.NewGuid():N}");
        var directory = Path.Combine(parent, "inner");
        Directory.CreateDirectory(directory);
        var file = Path.Combine(directory, "held.dll");
        File.WriteAllBytes(file, [1, 2, 3]);

        try
        {
            using (new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                Assert.ThrowsAny<IOException>(() => File.Move(file, file + ".moved"));
                Assert.ThrowsAny<Exception>(() => Directory.Move(directory, directory + ".moved"));
                Assert.ThrowsAny<Exception>(() => Directory.Move(parent, parent + ".moved"));
            }

            Assert.True(File.Exists(file));
        }
        finally
        {
            Directory.Delete(parent, recursive: true);
        }
    }

    private static string MappedFileNameOf(IntPtr module)
    {
        var name = new char[32_768];
        using var self = System.Diagnostics.Process.GetCurrentProcess();
        var length = K32GetMappedFileNameW(self.Handle, module, name, (uint)name.Length);
        Assert.True(length > 0, $"GetMappedFileName failed with error {Marshal.GetLastPInvokeError()}");
        return new string(name, 0, (int)length);
    }

    private static string LongPathOf(string path)
    {
        var buffer = new char[32_768];
        var length = GetLongPathNameW(path, buffer, (uint)buffer.Length);
        return length == 0 || length >= buffer.Length ? path : new string(buffer, 0, (int)length);
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint K32GetMappedFileNameW(IntPtr process, IntPtr address, char[] fileName, uint size);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetLongPathNameW(string shortPath, char[] longPath, uint size);

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
/// The decisions that settle a module's file, from what the kernel and the file system reported.
/// </summary>
public sealed class ModuleImageIdentityTests
{
    private const string Mapped = @"\Device\HarddiskVolume3\App\x.dll";

    [Fact]
    public void A_file_opened_under_the_mapped_name_that_the_mapping_still_carries_is_the_mapped_file()
    {
        Assert.Null(ModuleImageIdentity.WhyNotTheMappedFile(Mapped, Mapped, Mapped));
    }

    [Fact]
    public void Takes_the_file_systems_case_for_the_name_it_was_opened_under()
    {
        // The open used the kernel's exact string; only the echo of it may come back recased.
        Assert.Null(ModuleImageIdentity.WhyNotTheMappedFile(Mapped, Mapped.ToUpperInvariant(), Mapped));
    }

    [Fact]
    public void A_mapping_renamed_between_asking_and_opening_is_not_proven_to_be_the_file_opened()
    {
        // Rename the loaded DLL away after its name is read, put a signed one there before the open:
        // the open gets the signed one, and only asking again shows the mapping has moved.
        var reason = ModuleImageIdentity.WhyNotTheMappedFile(Mapped, Mapped, Mapped + ".old");

        Assert.NotNull(reason);
        Assert.Contains("renamed while it was being checked", reason);
    }

    [Fact]
    public void Compares_the_mapping_name_before_and_after_exactly_because_a_directory_can_be_case_sensitive()
    {
        // In a case-sensitive directory X.DLL and x.dll are two files: the loaded one renamed to the other
        // casing is a different name, and the signed one opened at the old casing is not it.
        Assert.NotNull(ModuleImageIdentity.WhyNotTheMappedFile(Mapped, Mapped, Mapped.ToUpperInvariant()));
    }

    [Fact]
    public void An_open_that_was_led_elsewhere_by_a_link_is_not_the_mapped_file()
    {
        var reason = ModuleImageIdentity.WhyNotTheMappedFile(
            Mapped, @"\Device\HarddiskVolume3\Windows\System32\version.dll", Mapped);

        Assert.NotNull(reason);
        Assert.Contains("reached", reason);
    }

    [Fact]
    public void A_mapping_that_can_no_longer_be_named_or_a_file_that_cannot_name_itself_proves_nothing()
    {
        Assert.NotNull(ModuleImageIdentity.WhyNotTheMappedFile(Mapped, Mapped, null));
        Assert.NotNull(ModuleImageIdentity.WhyNotTheMappedFile(Mapped, null, Mapped));
    }

    private static readonly FileIdentity Image = new(0xABCD, new UInt128(0, 42));

    [Fact]
    public void A_listed_path_naming_the_same_file_by_id_is_not_replaced()
    {
        Assert.False(ModuleImageIdentity.ListedPathIsOtherFile(null, Image, Image));
    }

    [Fact]
    public void A_listed_path_naming_another_file_or_another_volume_is_replaced()
    {
        Assert.True(ModuleImageIdentity.ListedPathIsOtherFile(null, Image with { FileId = 43 }, Image));
        Assert.True(ModuleImageIdentity.ListedPathIsOtherFile(null, Image with { VolumeSerial = 1 }, Image));
    }

    [Theory]
    [InlineData(2)] // ERROR_FILE_NOT_FOUND
    [InlineData(3)] // ERROR_PATH_NOT_FOUND
    public void A_listed_path_that_names_nothing_is_replaced(int error)
    {
        Assert.True(ModuleImageIdentity.ListedPathIsOtherFile(error, null, Image));
    }

    [Theory]
    [InlineData(5)]  // ERROR_ACCESS_DENIED
    [InlineData(32)] // ERROR_SHARING_VIOLATION
    [InlineData(123)] // ERROR_INVALID_NAME
    public void A_listed_path_this_server_could_not_open_is_unknown_not_replaced(int error)
    {
        // File.Exists said "gone" for all of these, and an unreadable directory became a confident
        // [REPLACED ON DISK] for a file nobody had touched.
        Assert.Null(ModuleImageIdentity.ListedPathIsOtherFile(error, null, Image));
    }

    [Fact]
    public void Zero_file_ids_agreeing_prove_nothing()
    {
        var zero = new FileIdentity(0xABCD, UInt128.Zero);

        Assert.Null(ModuleImageIdentity.ListedPathIsOtherFile(null, zero, zero));
        Assert.Null(ModuleImageIdentity.ListedPathIsOtherFile(null, Image, null));
    }

    private static readonly (char, string)[] Drives = [('C', @"\Device\HarddiskVolume1"), ('D', @"\Device\HarddiskVolume10")];

    [Fact]
    public void Turns_a_local_volume_name_into_its_drive_letter_path()
    {
        Assert.Equal(@"C:\App\x.dll", ModuleImageIdentity.LocalDosPath(@"\Device\HarddiskVolume1\App\x.dll", Drives));
        Assert.Equal(@"D:\App\x.dll", ModuleImageIdentity.LocalDosPath(@"\Device\HarddiskVolume10\App\x.dll", Drives));
    }

    [Theory]
    [InlineData(@"\Device\Mup\attacker\share\x.dll")]
    [InlineData(@"\Device\LanmanRedirector\;Z:0000\attacker\share\x.dll")]
    [InlineData(@"\Device\HarddiskVolume2\App\x.dll")]
    [InlineData(@"\Device\HarddiskVolume1")]
    public void Refuses_a_share_or_a_volume_without_a_local_letter(string ntName)
    {
        // Opening it would sign this server in to whoever serves the share; and a volume this server
        // has no letter for is not one it can name to open.
        Assert.Null(ModuleImageIdentity.LocalDosPath(ntName, Drives));
    }

    [Fact]
    public void Lists_every_directory_above_a_file_from_the_volume_root_down()
    {
        Assert.Equal([@"C:\", @"C:\Windows", @"C:\Windows\System32"],
            ModuleImageIdentity.DirectoriesAbove(@"C:\Windows\System32\ntdll.dll"));
        Assert.Equal([@"C:\"], ModuleImageIdentity.DirectoriesAbove(@"C:\x.dll"));
        Assert.Empty(ModuleImageIdentity.DirectoriesAbove(@"\Device\HarddiskVolume1\x.dll"));
    }

    private const string Users = "S-1-5-32-545";
    private const string AuthenticatedUsers = "S-1-5-11";
    private const string SomeUser = "S-1-5-21-1-2-3-1001";
    private const string TrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    private const uint ReadAndExecute = 0x1200A9;
    private const uint Modify = 0x1301BF;
    private const uint FullControl = 0x1F01FF;

    private static DirectoryAce Allow(string sid, uint mask, byte flags = 0) => new(0x0, flags, mask, sid);

    /// <summary>A System32-shaped directory: owned by TrustedInstaller, readable by users, theirs alone to change.</summary>
    private static DirectoryGuard Locked(string path, params DirectoryAce[] extra) =>
        new(path, null, false, TrustedInstaller,
        [
            Allow(TrustedInstaller, FullControl),
            Allow("S-1-5-18", Modify),
            Allow("S-1-5-32-544", Modify),
            Allow(Users, ReadAndExecute),
            // CREATOR OWNER, full control, inherit-only: grants nothing on this directory itself.
            Allow("S-1-3-0", 0x1000_0000, flags: 0x0B),
            .. extra
        ]);

    private static readonly DirectoryGuard Root = Locked(@"C:\");
    private static readonly DirectoryGuard Windows = Locked(@"C:\Windows");
    private static readonly DirectoryGuard System32 = Locked(@"C:\Windows\System32");

    [Fact]
    public void Trusts_a_path_only_system_administrators_and_trustedinstaller_can_change()
    {
        Assert.Null(ModuleImageIdentity.WhyItsPathMayHaveMoved([Root, Windows, System32]));
    }

    [Fact]
    public void Refuses_a_directory_a_user_can_rename_and_names_it()
    {
        // The CI failure: %TEMP% is the user's own, so its subdirectory was renamed away with the loaded
        // DLL inside and a signed copy put at the old path -- which the kernel went on naming.
        var temp = Locked(@"C:\Users\me\AppData\Local\Temp", Allow(SomeUser, FullControl));

        var reason = ModuleImageIdentity.WhyItsPathMayHaveMoved([Root, Locked(@"C:\Users"), temp]);

        Assert.NotNull(reason);
        Assert.StartsWith(@"C:\Users\me\AppData\Local\Temp lets " + SomeUser + " ", reason);
        Assert.EndsWith(ModuleImageIdentity.OnlyAdminPathsTrusted, reason);
    }

    [Fact]
    public void Names_the_directory_nearest_the_root_when_several_can_be_changed()
    {
        var reason = ModuleImageIdentity.WhyItsPathMayHaveMoved(
        [
            Root,
            Locked(@"C:\Apps", Allow(AuthenticatedUsers, Modify)),
            Locked(@"C:\Apps\Tool", Allow(SomeUser, FullControl))
        ]);

        Assert.StartsWith(@"C:\Apps lets " + AuthenticatedUsers + " ", reason);
    }

    [Theory]
    [InlineData(0x0001_0000u)] // DELETE: renames it
    [InlineData(0x0004_0000u)] // WRITE_DAC: grants itself DELETE
    [InlineData(0x0008_0000u)] // WRITE_OWNER: takes it, then grants itself DELETE
    [InlineData(0x1000_0000u)] // GENERIC_ALL
    [InlineData(0x0200_0000u)] // MAXIMUM_ALLOWED, meaningless in an ACE and so read as everything
    public void Refuses_any_right_that_renames_a_directory_or_grants_the_right_to(uint mask)
    {
        Assert.NotNull(ModuleImageIdentity.WhyItsPathMayHaveMoved([Root, Windows, Locked(@"C:\Windows\x", Allow(Users, mask))]));
    }

    [Fact]
    public void Refuses_the_right_to_rename_what_is_in_a_directory_above_the_files_own()
    {
        // FILE_DELETE_CHILD on C:\Apps renames C:\Apps\Tool, the file's own directory.
        var reason = ModuleImageIdentity.WhyItsPathMayHaveMoved(
            [Root, Locked(@"C:\Apps", Allow(Users, 0x40)), Locked(@"C:\Apps\Tool")]);

        Assert.StartsWith(@"C:\Apps lets " + Users + " rename or delete what is in it", reason);
    }

    [Fact]
    public void Lets_a_user_rename_the_file_itself_because_the_kernels_name_follows_that()
    {
        // FILE_DELETE_CHILD on the file's own directory renames only the file, and the kernel's name for
        // the mapping does follow that; the before-and-after comparison is what catches it.
        Assert.Null(ModuleImageIdentity.WhyItsPathMayHaveMoved([Root, Windows, Locked(@"C:\Windows\x", Allow(Users, 0x40))]));
    }

    [Fact]
    public void Lets_users_delete_on_the_volume_root_because_a_root_cannot_be_renamed()
    {
        Assert.Null(ModuleImageIdentity.WhyItsPathMayHaveMoved([Locked(@"D:\", Allow(AuthenticatedUsers, Modify)), Locked(@"D:\Tool")]));
    }

    [Fact]
    public void Refuses_a_root_that_lets_a_user_rename_what_is_in_it()
    {
        Assert.NotNull(ModuleImageIdentity.WhyItsPathMayHaveMoved([Locked(@"D:\", Allow(Users, 0x40)), Locked(@"D:\Tool")]));
    }

    [Fact]
    public void Ignores_inherit_only_and_deny_entries_and_reading_and_writing_rights()
    {
        // Inherit-only grants nothing here; a deny never grants; GENERIC_WRITE and Write do not include
        // DELETE or FILE_DELETE_CHILD. C:\'s own "Users: create folders" is the same kind of right.
        var guard = Locked(@"C:\Windows\x",
            Allow(AuthenticatedUsers, Modify, flags: 0x0B),
            new DirectoryAce(0x1, 0, FullControl, Users),
            Allow(Users, 0x4000_0000),
            Allow(Users, 0x0012_0116), // FILE_GENERIC_WRITE
            Allow(Users, 0x4));

        Assert.Null(ModuleImageIdentity.WhyItsPathMayHaveMoved([Root, Windows, guard]));
    }

    [Fact]
    public void Refuses_a_directory_owned_by_anyone_else_because_an_owner_can_grant_itself_anything()
    {
        var reason = ModuleImageIdentity.WhyItsPathMayHaveMoved([Root, Locked(@"C:\Tool") with { Owner = SomeUser }]);

        Assert.StartsWith($@"C:\Tool is owned by {SomeUser}", reason);
    }

    [Fact]
    public void Refuses_a_null_dacl_an_unreadable_directory_and_a_link_on_the_path()
    {
        Assert.Contains("no access list", ModuleImageIdentity.WhyItsPathMayHaveMoved([Root, Locked(@"C:\Tool") with { Dacl = null }]));
        Assert.Contains("could not be examined (error 5",
            ModuleImageIdentity.WhyItsPathMayHaveMoved([Root, DirectoryGuard.Unreadable(@"C:\Tool", "error 5: Access is denied.")]));
        Assert.Contains("link or mount point", ModuleImageIdentity.WhyItsPathMayHaveMoved([Root, Locked(@"C:\Tool") with { IsReparsePoint = true }]));
        Assert.NotNull(ModuleImageIdentity.WhyItsPathMayHaveMoved([]));
    }

    [Fact]
    public void Refuses_an_allow_entry_it_cannot_read_and_reads_a_conditional_allow_as_unconditional()
    {
        // An object ACE (type 5) is laid out differently and not read: guessing would be failing open.
        Assert.Contains("type 0x05", ModuleImageIdentity.WhyItsPathMayHaveMoved(
            [Root, Locked(@"C:\Tool", new DirectoryAce(0x5, 0, 0, null))]));

        // A callback allow (type 9) may hold under conditions this server cannot evaluate; assume it does.
        Assert.NotNull(ModuleImageIdentity.WhyItsPathMayHaveMoved(
            [Root, Locked(@"C:\Tool", new DirectoryAce(0x9, 0, FullControl, Users))]));
    }
}

/// <summary>
/// How the inspector turns each module's held file -- or its absence -- into what it reports, driven
/// through hand-written fakes so it runs anywhere.
/// </summary>
public sealed class ModuleAssemblyTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"windiag-assemble-{Guid.NewGuid():N}");

    public ModuleAssemblyTests() => Directory.CreateDirectory(_directory);

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private static WindowsModuleInspector Inspector(ISignatureInspector signatures, int maxResults = 1000) =>
        new(signatures, WinDiagOptions.FromEnvironment(new System.Collections.Hashtable
        {
            ["WINDIAG_MAX_RESULTS"] = maxResults.ToString(System.Globalization.CultureInfo.InvariantCulture)
        }));

    private string ImageFile(string name, int peOffset = 0x80)
    {
        var path = Path.Combine(_directory, name);
        File.WriteAllBytes(path, PeImageReaderTests.SyntheticImage(peOffset, imageBase: 0x1000_0000, dynamicBase: false));
        return path;
    }

    private static ListedModule Listed(string name, ulong at = 0x7FF8_0000_0000) =>
        new(name, $@"C:\App\{name}", at, 4096);

    [Fact]
    public void Gives_a_module_whose_file_could_not_be_identified_no_verdict_rather_than_its_paths()
    {
        // The fail-open: identity unknown (a header built not to parse, a file held open to make the
        // comparison fail) and the module was verified by its path anyway -- a signed file put there came
        // back Valid, and the unsigned code running dropped out of the count.
        var signatures = new RecordingSignatureInspector();
        var images = new FakeImageSource
        {
            ["hidden.dll"] = () => ModuleImageFile.Unknown("the kernel did not name the file mapped at 0x1"),
            ["app.dll"] = () => Identified(ImageFile("app.dll"), listedOther: false)
        };

        var result = Inspector(signatures).Assemble(
            42, "app", [Listed("hidden.dll"), Listed("app.dll")], null, images, null, true, CancellationToken.None);

        var hidden = result.Modules.Single(m => m.Name == "hidden.dll");
        Assert.Equal(LoadedModule.NotVerified, hidden.SignatureVerdict);
        Assert.Null(hidden.Signer);
        Assert.Null(hidden.FileVersion);
        Assert.Null(hidden.PreferredBase);
        Assert.Null(hidden.ReplacedOnDisk);
        Assert.Equal("the kernel did not name the file mapped at 0x1", hidden.ImageFileUnknownReason);

        Assert.Equal("Valid", result.Modules.Single(m => m.Name == "app.dll").SignatureVerdict);
        Assert.Equal([Path.Combine(_directory, "app.dll")], signatures.HeldPaths);
        Assert.Empty(signatures.ByPath);
        Assert.Equal(1, result.NotVerifiedCount);
        Assert.Equal(1, result.UnidentifiedCount);
        Assert.Equal(0, result.UnsignedCount);
        Assert.DoesNotContain("Every module returned is signed", ModuleTools.Render(result, null, true));
    }

    [Fact]
    public void Verifies_through_the_very_handle_that_identified_the_file_while_it_is_still_held()
    {
        // The TOCTOU: identity settled during enumeration, signature checked much later by reopening the
        // path, and a swap in between got the swapped-in file's verdict. One handle, still open.
        var signatures = new RecordingSignatureInspector();
        FileStream? handedOut = null;
        var images = new FakeImageSource
        {
            ["app.dll"] = () =>
            {
                var image = Identified(ImageFile("app.dll"), listedOther: false);
                handedOut = image.Held;
                return image;
            }
        };

        Inspector(signatures).Assemble(42, "app", [Listed("app.dll")], null, images, null, true, CancellationToken.None);

        var call = Assert.Single(signatures.HeldCalls);
        Assert.Same(handedOut, call.Stream);
        Assert.True(call.WasOpen);
        Assert.True(handedOut!.SafeFileHandle.IsClosed, "the hold must end once the module is described");
    }

    [Fact]
    public void Reports_a_replaced_module_from_its_loaded_file_and_says_where_that_is()
    {
        var signatures = new RecordingSignatureInspector { Verdict = SignatureVerdict.Unsigned };
        var loaded = ImageFile("evil.dll.old");
        var images = new FakeImageSource { ["evil.dll"] = () => Identified(loaded, listedOther: true) };

        var result = Inspector(signatures).Assemble(
            42, "app", [Listed("evil.dll", at: 0x1000_0000)], null, images, null, true, CancellationToken.None);

        var module = Assert.Single(result.Modules);
        Assert.True(module.ReplacedOnDisk);
        Assert.Equal(loaded, module.ImageFilePath);
        Assert.Equal("Unsigned", module.SignatureVerdict);
        Assert.Equal("0x10000000", module.PreferredBase);
        Assert.False(module.Relocated);
        Assert.Equal(1, result.ReplacedCount);
        Assert.Equal(1, result.UnsignedCount);
    }

    [Fact]
    public void Reads_the_preferred_base_through_the_held_file_however_far_in_its_headers_are()
    {
        var images = new FakeImageSource { ["legacy.dll"] = () => Identified(ImageFile("legacy.dll", peOffset: 0x1400), listedOther: false) };

        var result = Inspector(new RecordingSignatureInspector()).Assemble(
            42, "app", [Listed("legacy.dll")], null, images, null, false, CancellationToken.None);

        var module = Assert.Single(result.Modules);
        Assert.Equal("0x10000000", module.PreferredBase);
        Assert.True(module.BaseCollision);
        Assert.Null(module.ImageFilePath);
        Assert.Null(module.SignatureVerdict);
    }

    [Fact]
    public void Counts_replaced_and_unidentified_modules_past_the_returned_page_but_verifies_only_the_page()
    {
        var signatures = new RecordingSignatureInspector();
        var images = new FakeImageSource
        {
            ["a.dll"] = () => Identified(ImageFile("a.dll"), listedOther: false),
            ["b.dll"] = () => Identified(ImageFile("b.dll"), listedOther: true),
            ["c.dll"] = () => ModuleImageFile.Unknown("no")
        };

        var result = Inspector(signatures, maxResults: 1).Assemble(
            42, "app", [Listed("c.dll"), Listed("b.dll"), Listed("a.dll")], null, images, null, true, CancellationToken.None);

        Assert.Equal("a.dll", Assert.Single(result.Modules).Name);
        Assert.True(result.Truncated);
        Assert.Equal(1, result.ReplacedCount);
        Assert.Equal(1, result.UnidentifiedCount);
        Assert.Single(signatures.HeldCalls);
        Assert.Equal(3, images.Opened);
        Assert.Equal(3, images.Disposed);
    }

    private static ModuleImageFile Identified(string path, bool? listedOther) =>
        ModuleImageFile.Identified(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read), path, listedOther);

    /// <summary>Hands out the image file each module name is mapped to here, and counts what it handed out.</summary>
    private sealed class FakeImageSource : Dictionary<string, Func<ModuleImageFile>>, IModuleImageSource
    {
        private readonly List<ModuleImageFile> _handedOut = [];

        public int Opened => _handedOut.Count;

        public int Disposed => _handedOut.Count(f => f.Held is null || f.Held.SafeFileHandle.IsClosed);

        public ModuleImageFile Open(string listedPath, ulong baseAddress)
        {
            // Keyed by the listed path's last component, split by hand: these paths are Windows ones, and
            // Path.GetFileName would not split them on the other platforms this runs on.
            var file = this[listedPath[(listedPath.LastIndexOf('\\') + 1)..]]();
            _handedOut.Add(file);
            return file;
        }

        public void Dispose()
        {
        }
    }

    /// <summary>Gives every file it is asked about one verdict, and records how it was asked.</summary>
    private sealed class RecordingSignatureInspector : ISignatureInspector
    {
        public SignatureVerdict Verdict { get; init; } = SignatureVerdict.Valid;

        public List<string> ByPath { get; } = [];

        public List<(string Path, FileStream Stream, bool WasOpen)> HeldCalls { get; } = [];

        public List<string> HeldPaths => [.. HeldCalls.Select(c => c.Path)];

        public SignatureQueryResult Inspect(IReadOnlyList<string> paths, CancellationToken cancellationToken)
        {
            ByPath.AddRange(paths);
            return new SignatureQueryResult([.. paths.Select(Signature)], []);
        }

        public FileSignature InspectHeld(string path, CancellationToken cancellationToken) =>
            throw new NotSupportedException("module verification holds the file itself");

        public FileSignature InspectHeld(string path, FileStream held, CancellationToken cancellationToken)
        {
            HeldCalls.Add((path, held, !held.SafeFileHandle.IsClosed));
            return Signature(path);
        }

        private FileSignature Signature(string path) =>
            new(path, Verdict, "fake", false, "Microsoft Windows", null, null, null, null, null, null, 1,
                DateTimeOffset.UnixEpoch, "00");
    }
}
