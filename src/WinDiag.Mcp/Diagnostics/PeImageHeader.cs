using System.Buffers.Binary;

namespace WinDiag.Mcp.Diagnostics;

/// <summary>The PE header fields this server needs: where an image wanted to load, and what it runs on.</summary>
/// <param name="ImageBase">The address the linker chose.</param>
/// <param name="DynamicBase">
/// True when the image carries <c>IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE</c>, i.e. it was built to be
/// relocated by ASLR and being moved says nothing about it.
/// </param>
/// <param name="Machine">
/// The COFF machine type: <c>0x014C</c> for x86, <c>0x8664</c> for x64, <c>0xAA64</c> for ARM64. The
/// only reliable way to tell a Sysinternals 32-bit launcher from the real thing, since both are named
/// the same.
/// </param>
/// <remarks>
/// Nothing here says which file an image is. Every field is the builder's to choose, and the loader
/// rewrites some of them in the copy it maps (ImageBase always; Machine for an ARM64X image in an x64
/// process, or an IL-only PE32 in a 64-bit one), so two headers agreeing proves nothing about two files
/// being the same -- which is why <c>process_modules</c> settles that from the kernel's name for the
/// mapped file, and from who could have changed the directories on that name, instead.
/// </remarks>
public readonly record struct PeImageHeader(ulong ImageBase, bool DynamicBase, ushort Machine)
{
    public const ushort MachineI386 = 0x014C;
    public const ushort MachineAmd64 = 0x8664;
    public const ushort MachineArm64 = 0xAA64;

    /// <summary>True for an image that cannot run as a 64-bit process.</summary>
    public bool Is32Bit => Machine == MachineI386;
}

/// <summary>
/// Reads the few PE header fields this server acts on, without a metadata reader.
/// </summary>
/// <remarks>
/// Two callers, both of which need an answer a file name cannot give. Module listing pairs
/// <c>ImageBase</c> with the address a module actually got, because a load address on its own is a
/// number the caller cannot act on. External tool resolution reads <c>Machine</c>, because the
/// Sysinternals downloads ship a 32-bit launcher and the real 64-bit binary under names that differ by
/// one character -- and picking wrong produces a plausible wrong answer rather than an error.
///
/// Deliberately a raw header read rather than <c>System.Reflection.PortableExecutable</c>: the fields
/// are at fixed offsets, the file may be a native image with no managed metadata at all, and this runs
/// once per module in a list that can be several hundred long.
/// </remarks>
public static class PeImageReader
{
    private const int DosHeaderSize = 64;
    private const ushort DosSignature = 0x5A4D; // "MZ", little-endian
    private const int DosHeaderLfaNewOffset = 0x3C;
    private const uint PeSignature = 0x0000_4550; // "PE\0\0", little-endian
    private const int CoffHeaderSize = 20;
    private const ushort Pe32Magic = 0x010B;
    private const ushort Pe32PlusMagic = 0x020B;
    private const int Pe32ImageBaseOffset = 28;
    private const int Pe32PlusImageBaseOffset = 24;

    // Same offset in both optional-header layouts: PE32+ drops BaseOfData (4 bytes) but widens
    // ImageBase by the same 4, so everything from SectionAlignment onwards realigns.
    private const int DllCharacteristicsOffset = 70;
    private const ushort DynamicBaseFlag = 0x0040;

    /// <summary>The signature, COFF header and as much of the optional header as is read.</summary>
    private const int NtHeaderBytes = 4 + CoffHeaderSize + DllCharacteristicsOffset + 2;

    /// <summary>
    /// The loader's own ceiling on <c>e_lfanew</c> (<c>RtlImageNtHeaderEx</c> refuses 256 MB and over,
    /// whatever the file's length).
    /// </summary>
    /// <remarks>
    /// The bound is the loader's, not a buffer's. This used to read the first kilobyte and refuse an
    /// <c>e_lfanew</c> past it, which the loader accepts: an image built that way loads, runs, and came
    /// back here as "not a PE" -- a check its author could switch off at will.
    /// </remarks>
    private const int MaxLfaNew = 0x1000_0000;

    /// <summary>Reads the header, or returns null if the file cannot be read or is not a PE image.</summary>
    /// <remarks>
    /// Never throws for a caller's benefit: a file that is gone, unreadable or not an image is a normal
    /// thing to meet, and it must not cost the rest of a list.
    /// </remarks>
    public static PeImageHeader? TryRead(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            // FileShare.ReadWrite|Delete: these files may be mapped into a running process, and on
            // Windows a pending-delete image still opens only for a sharer that says so.
            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1);

            return TryRead(stream);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                      or NotSupportedException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// Reads the header through a stream the caller already holds, so the answer is about that file and
    /// not whatever its path names by the time a second open would happen.
    /// </summary>
    /// <remarks>Seeks; the caller must not rely on the stream's position afterwards.</remarks>
    public static PeImageHeader? TryRead(Stream stream)
    {
        try
        {
            Span<byte> dos = stackalloc byte[DosHeaderSize];
            stream.Seek(0, SeekOrigin.Begin);
            if (stream.ReadAtLeast(dos, dos.Length, throwOnEndOfStream: false) < dos.Length
                || BinaryPrimitives.ReadUInt16LittleEndian(dos) != DosSignature)
            {
                return null;
            }

            var peOffset = BinaryPrimitives.ReadInt32LittleEndian(dos[DosHeaderLfaNewOffset..]);
            if (peOffset is < 0 or >= MaxLfaNew)
            {
                return null;
            }

            // Short means the headers run past the end of the file, which the loader refuses too.
            Span<byte> nt = stackalloc byte[NtHeaderBytes];
            stream.Seek(peOffset, SeekOrigin.Begin);
            if (stream.ReadAtLeast(nt, nt.Length, throwOnEndOfStream: false) < nt.Length)
            {
                return null;
            }

            return ParseNtHeaders(nt);
        }
        catch (Exception ex) when (ex is IOException or NotSupportedException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Reads the fields from the NT headers: signature, COFF header, optional header.</summary>
    private static PeImageHeader? ParseNtHeaders(ReadOnlySpan<byte> nt)
    {
        if (BinaryPrimitives.ReadUInt32LittleEndian(nt) != PeSignature)
        {
            return null;
        }

        // The COFF header opens with the machine type, immediately after the signature.
        var machine = BinaryPrimitives.ReadUInt16LittleEndian(nt[4..]);

        var optional = nt[(4 + CoffHeaderSize)..];
        var imageBase = BinaryPrimitives.ReadUInt16LittleEndian(optional) switch
        {
            Pe32Magic => BinaryPrimitives.ReadUInt32LittleEndian(optional[Pe32ImageBaseOffset..]),
            Pe32PlusMagic => BinaryPrimitives.ReadUInt64LittleEndian(optional[Pe32PlusImageBaseOffset..]),
            _ => 0UL
        };

        // Zero is never a mapped image's base, and a ROM or unknown magic does not load.
        if (imageBase == 0)
        {
            return null;
        }

        var characteristics = BinaryPrimitives.ReadUInt16LittleEndian(optional[DllCharacteristicsOffset..]);

        return new PeImageHeader(imageBase, (characteristics & DynamicBaseFlag) != 0, machine);
    }
}
