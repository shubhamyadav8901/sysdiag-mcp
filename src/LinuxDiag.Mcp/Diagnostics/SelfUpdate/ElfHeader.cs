using System.Buffers.Binary;

namespace LinuxDiag.Mcp.Diagnostics.SelfUpdate;

/// <summary>Is this file something this machine can run in this server's place?</summary>
public static class ElfHeader
{
    private const ushort MachineX86_64 = 0x3E;

    /// <returns>Null when the header is an x86-64, little-endian, 64-bit executable; otherwise why not.</returns>
    public static string? Problem(ReadOnlySpan<byte> header)
    {
        if (header.Length < 20 || header[0] != 0x7F || header[1] != 'E' || header[2] != 'L' || header[3] != 'F')
        {
            return "it is not a Linux executable: it does not start with the ELF signature. A Windows " +
                   ".exe or a script staged by mistake would leave this server unable to come back.";
        }

        if (header[4] != 2 || header[5] != 1)
        {
            return "it is a 32-bit or big-endian ELF file, and this server is x86-64.";
        }

        var type = BinaryPrimitives.ReadUInt16LittleEndian(header[16..]);
        if (type is not (2 or 3))
        {
            return $"it is an ELF file of type {type}, not an executable.";
        }

        var machine = BinaryPrimitives.ReadUInt16LittleEndian(header[18..]);
        return machine == MachineX86_64
            ? null
            : $"it is built for ELF machine type 0x{machine:X}, not x86-64.";
    }
}
