using System.Buffers.Binary;

namespace WinDiag.Mcp.Diagnostics.Modules;

/// <summary>The two PE fields that say where an image wanted to load, and whether it minded moving.</summary>
/// <param name="ImageBase">The address the linker chose.</param>
/// <param name="DynamicBase">
/// True when the image carries <c>IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE</c>, i.e. it was built to be
/// relocated by ASLR and being moved says nothing about it.
/// </param>
public readonly record struct PeImageHeader(ulong ImageBase, bool DynamicBase);

/// <summary>
/// Reads a PE file's preferred load address, so a loaded module's actual base means something.
/// </summary>
/// <remarks>
/// A base address on its own is a number the caller cannot act on. Paired with what the file asked for,
/// it answers the question listdlls exists to answer -- did this DLL get rebased, and did it mind.
///
/// Deliberately a raw header read rather than <c>System.Reflection.PortableExecutable</c>: the fields
/// are at fixed offsets, the file may be a native image with no managed metadata at all, and this runs
/// once per module in a list that can be several hundred long.
/// </remarks>
internal static class PeImageReader
{
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

            // The optional header cannot start further in than this and still be a real image; the read
            // is one buffer so a short or truncated file fails on length rather than on seeking.
            Span<byte> header = stackalloc byte[1024];
            var read = stream.ReadAtLeast(header, header.Length, throwOnEndOfStream: false);
            if (read < DosHeaderLfaNewOffset + 4)
            {
                return null;
            }

            header = header[..read];

            var peOffset = BinaryPrimitives.ReadInt32LittleEndian(header[DosHeaderLfaNewOffset..]);
            if (peOffset < 0 || peOffset + 4 + CoffHeaderSize + DllCharacteristicsOffset + 2 > header.Length)
            {
                return null;
            }

            if (BinaryPrimitives.ReadUInt32LittleEndian(header[peOffset..]) != PeSignature)
            {
                return null;
            }

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

            return new PeImageHeader(imageBase, (characteristics & DynamicBaseFlag) != 0);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                      or NotSupportedException or ArgumentException)
        {
            return null;
        }
    }
}
