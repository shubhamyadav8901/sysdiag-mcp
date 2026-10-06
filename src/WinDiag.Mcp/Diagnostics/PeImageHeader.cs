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
/// <param name="TimeDateStamp">The COFF link stamp (a content hash under reproducible builds).</param>
/// <param name="SizeOfImage">How much address space the image occupies once mapped.</param>
/// <param name="CheckSum">The optional header's checksum; zero for most images that are not drivers.</param>
public readonly record struct PeImageHeader(
    ulong ImageBase,
    bool DynamicBase,
    ushort Machine,
    uint TimeDateStamp,
    uint SizeOfImage,
    uint CheckSum)
{
    public const ushort MachineI386 = 0x014C;
    public const ushort MachineAmd64 = 0x8664;
    public const ushort MachineArm64 = 0xAA64;

    /// <summary>True for an image that cannot run as a 64-bit process.</summary>
    public bool Is32Bit => Machine == MachineI386;

    /// <summary>
    /// True when two headers describe the same build of an image: same machine, link stamp, mapped size
    /// and checksum.
    /// </summary>
    /// <remarks>
    /// <c>ImageBase</c> is deliberately not compared. The loader writes the address an image actually got
    /// into the header it maps, so a relocated module's in-memory header and its own file disagree there
    /// by design. These four fields the loader never touches. Identity of the header, not of every byte:
    /// a file patched in place with its header kept would still match.
    /// </remarks>
    public bool IsSameBuildAs(PeImageHeader other) =>
        Machine == other.Machine
        && TimeDateStamp == other.TimeDateStamp
        && SizeOfImage == other.SizeOfImage
        && CheckSum == other.CheckSum;
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
    private const int DosHeaderLfaNewOffset = 0x3C;
    private const uint PeSignature = 0x0000_4550; // "PE\0\0", little-endian
    private const int CoffHeaderSize = 20;
    private const ushort Pe32Magic = 0x010B;
    private const ushort Pe32PlusMagic = 0x020B;
    private const int Pe32ImageBaseOffset = 28;
    private const int Pe32PlusImageBaseOffset = 24;
    private const int CoffTimeDateStampOffset = 4;

    // Same offsets in both optional-header layouts, for the same reason as DllCharacteristics below.
    private const int SizeOfImageOffset = 56;
    private const int CheckSumOffset = 64;

    /// <summary>
    /// How many leading bytes of an image <see cref="TryParse"/> needs. The optional header cannot start
    /// further in than this and still be a real image.
    /// </summary>
    public const int HeaderBytes = 1024;

    // Same offset in both optional-header layouts: PE32+ drops BaseOfData (4 bytes) but widens
    // ImageBase by the same 4, so everything from SectionAlignment onwards realigns.
    private const int DllCharacteristicsOffset = 70;
    private const ushort DynamicBaseFlag = 0x0040;

    /// <summary>Reads the header, or returns null if the file cannot be read or is not a PE image.</summary>
    /// <remarks>
    /// Never throws for a caller's benefit: a module whose file has been deleted or replaced under the
    /// running process is a normal thing to meet, and it must not cost the rest of the list.
    /// </remarks>
    public static PeImageHeader? TryRead(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            // FileShare.ReadWrite|Delete: these files are mapped into a running process, and on Windows
            // a pending-delete image still opens only for a sharer that says so.
            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096);

            // One buffer, so a short or truncated file fails on length rather than on seeking.
            Span<byte> header = stackalloc byte[HeaderBytes];
            var read = stream.ReadAtLeast(header, header.Length, throwOnEndOfStream: false);

            return TryParse(header[..read]);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                      or NotSupportedException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// Reads the header from an image's leading bytes, wherever they came from -- a file, or a module's
    /// mapping in another process. Null when they are not a PE header.
    /// </summary>
    public static PeImageHeader? TryParse(ReadOnlySpan<byte> header)
    {
        if (header.Length < DosHeaderLfaNewOffset + 4)
        {
            return null;
        }

        // In long arithmetic: these bytes may come from another process's memory, and an e_lfanew near
        // int.MaxValue would otherwise wrap past this check into an out-of-range slice.
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(header[DosHeaderLfaNewOffset..]);
        if (peOffset < 0 || (long)peOffset + 4 + CoffHeaderSize + DllCharacteristicsOffset + 2 > header.Length)
        {
            return null;
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(header[peOffset..]) != PeSignature)
        {
            return null;
        }

        // The COFF header opens with the machine type, immediately after the signature.
        var machine = BinaryPrimitives.ReadUInt16LittleEndian(header[(peOffset + 4)..]);

        var optional = header[(peOffset + 4 + CoffHeaderSize)..];
        var magic = BinaryPrimitives.ReadUInt16LittleEndian(optional);

        var imageBase = magic switch
        {
            Pe32Magic => BinaryPrimitives.ReadUInt32LittleEndian(optional[Pe32ImageBaseOffset..]),
            Pe32PlusMagic => BinaryPrimitives.ReadUInt64LittleEndian(optional[Pe32PlusImageBaseOffset..]),
            _ => 0UL
        };

        if (imageBase == 0)
        {
            return null;
        }

        var characteristics = BinaryPrimitives.ReadUInt16LittleEndian(optional[DllCharacteristicsOffset..]);

        return new PeImageHeader(
            imageBase,
            (characteristics & DynamicBaseFlag) != 0,
            machine,
            TimeDateStamp: BinaryPrimitives.ReadUInt32LittleEndian(header[(peOffset + 4 + CoffTimeDateStampOffset)..]),
            SizeOfImage: BinaryPrimitives.ReadUInt32LittleEndian(optional[SizeOfImageOffset..]),
            CheckSum: BinaryPrimitives.ReadUInt32LittleEndian(optional[CheckSumOffset..]));
    }
}
