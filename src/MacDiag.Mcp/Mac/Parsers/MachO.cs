using System.Buffers.Binary;

namespace MacDiag.Mcp.Mac.Parsers;

/// <param name="Problem">Why this Mac cannot run the file in the server's place; null when it can.</param>
/// <param name="CpuType">The slice that will run: what decides whether its signature matters.</param>
public sealed record MachOVerdict(string? Problem, int? CpuType);

/// <summary>Is this file something this Mac can run in the server's place? Read from its headers alone.</summary>
/// <remarks>
/// <para>A thin Mach-O is little-endian on disk (CF FA ED FE); a universal binary's header and slice table are
/// big-endian (CA FE BA BE). A Java class file starts with the same four bytes, followed by its major version
/// (45 and up) where a universal binary has its slice count, so a count above 8 is a class file, not a binary.</para>
/// <para>The slice that runs is decided by this Mac, not by this process: under Rosetta the server is x86-64, yet
/// launchd starts the arm64 slice of a universal build on Apple Silicon.</para>
/// </remarks>
public static class MachO
{
    public const int CpuTypeArm64 = 0x0100000C;
    public const int CpuTypeX86_64 = 0x01000007;
    private const uint MhExecute = 2;
    private const int MaxSlices = 8;

    /// <param name="read">Reads up to count bytes at an offset; fewer at the end of the file.</param>
    /// <param name="preferArm64">This Mac is Apple Silicon.</param>
    /// <param name="rosettaInstalled">Whether an Intel build can run here at all.</param>
    public static MachOVerdict Inspect(Func<long, int, byte[]> read, bool preferArm64, Func<bool> rosettaInstalled)
    {
        ArgumentNullException.ThrowIfNull(read);
        ArgumentNullException.ThrowIfNull(rosettaInstalled);

        var header = read(0, 32);
        if (header.Length < 32)
        {
            return Refused("it is too short to be an executable.");
        }

        var magic = BinaryPrimitives.ReadUInt32BigEndian(header);
        switch (magic)
        {
            case 0xCFFAEDFE:
                return Thin(header, expectedCpu: null, preferArm64, rosettaInstalled);
            case 0xCAFEBABE:
                return Universal(read, BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(4)), preferArm64, rosettaInstalled);
            case 0xCAFEBABF:
                return Refused("it is a 64-bit universal binary, which this server does not accept; publish it with dotnet publish -r osx-arm64 or osx-x64.");
            case 0x7F454C46:
                return Refused("it is a Linux executable, not a macOS one.");
            case 0xFEEDFACF or 0xFEEDFACE or 0xCEFAEDFE:
                return Refused("it is not a 64-bit little-endian Mach-O executable.");
        }

        return header[0] == 'M' && header[1] == 'Z'
            ? Refused("it is a Windows executable, not a macOS one.")
            : Refused("it is not a Mach-O executable (it may be a script or an archive).");
    }

    private static MachOVerdict Universal(Func<long, int, byte[]> read, uint slices, bool preferArm64, Func<bool> rosettaInstalled)
    {
        if (slices > MaxSlices)
        {
            return Refused("it is not a Mach-O executable (it looks like a Java class file).");
        }

        if (slices == 0)
        {
            return Refused("it is a universal binary with no slices.");
        }

        var table = read(8, (int)(20 * slices));
        if (table.Length < 20 * slices)
        {
            return Refused("its universal header is cut off.");
        }

        var entries = Enumerable.Range(0, (int)slices)
            .Select(i => (Cpu: BinaryPrimitives.ReadInt32BigEndian(table.AsSpan(20 * i)), Offset: BinaryPrimitives.ReadUInt32BigEndian(table.AsSpan((20 * i) + 8))))
            .ToList();

        (int Cpu, uint Offset)? chosen =
            preferArm64 && entries.Any(e => e.Cpu == CpuTypeArm64) ? entries.First(e => e.Cpu == CpuTypeArm64)
            : entries.Any(e => e.Cpu == CpuTypeX86_64) ? entries.First(e => e.Cpu == CpuTypeX86_64)
            : entries.Any(e => e.Cpu == CpuTypeArm64) ? entries.First(e => e.Cpu == CpuTypeArm64)
            : null;
        if (chosen is not { } slice)
        {
            return Refused("it has no slice for an Apple Silicon or Intel Mac.");
        }

        var sliceHeader = read(slice.Offset, 32);
        return sliceHeader.Length < 32 || BinaryPrimitives.ReadUInt32BigEndian(sliceHeader) != 0xCFFAEDFE
            ? Refused("the slice this Mac would run is missing or cut off.")
            : Thin(sliceHeader, slice.Cpu, preferArm64, rosettaInstalled);
    }

    private static MachOVerdict Thin(byte[] header, int? expectedCpu, bool preferArm64, Func<bool> rosettaInstalled)
    {
        var cpu = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(4));
        var fileType = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(12));
        if (expectedCpu is { } expected && cpu != expected)
        {
            return Refused("its slice table and the slice it points at disagree about the processor.");
        }

        if (fileType != MhExecute)
        {
            return Refused("it is not an executable (a library or bundle).");
        }

        return cpu switch
        {
            CpuTypeArm64 when !preferArm64 => Refused("this Mac cannot run an arm64 build; it is an Intel Mac. Stage an osx-x64 or universal build."),
            CpuTypeArm64 => new MachOVerdict(null, cpu),
            CpuTypeX86_64 when preferArm64 && !rosettaInstalled() => Refused("it is an Intel build, and Rosetta is not installed on this Mac. Stage an osx-arm64 build."),
            CpuTypeX86_64 => new MachOVerdict(null, cpu),
            _ => Refused("it is built for another processor."),
        };
    }

    private static MachOVerdict Refused(string why) => new(why, null);
}

/// <summary>The verdict codesign -dv gives a file, from its standard error, where codesign writes it.</summary>
public static class CodesignDisplay
{
    /// <summary>
    /// codesign arguments that succeed only when Apple itself signed <paramref name="path"/>: the chain is checked by the
    /// Security framework against Apple's anchor, which a Developer ID or App Store signature does not satisfy.
    /// </summary>
    /// <remarks>
    /// Not the leaf's name from -dvvv. Anyone can make a certificate called "Software Signing", and --verify accepts a
    /// self-signed chain, so a name match reported a home-made signature as Apple's. The name is not stable either:
    /// macOS 26 calls the leaf "macOS Software Signing" (measured on 26.6.2). codesign exits 3 when the requirement fails.
    /// </remarks>
    public static IReadOnlyList<string> AppleAnchoredArguments(string path) => ["--verify", "--strict", "-R=anchor apple", "--", path];

    /// <summary>A leaf that is not Apple's, quoted as the signer named it.</summary>
    /// <remarks>
    /// Always quoted and labelled, never bare: the name is the signer's choice, so a certificate called "Apple" printed
    /// as "Signed by Apple" would read exactly like the anchor-checked verdict.
    /// </remarks>
    public static string Certificate(string leaf) => $"certificate \"{leaf.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal)}\"";

    public static (string Verdict, string? Detail) Verdict(int exitCode, string standardError)
    {
        var text = standardError ?? string.Empty;
        if (text.Contains("code object is not signed at all", StringComparison.Ordinal))
        {
            return ("NotSigned", null);
        }

        if (exitCode != 0)
        {
            return ("Unknown", text.Trim());
        }

        if (text.Contains("Signature=adhoc", StringComparison.Ordinal))
        {
            return ("AdHoc", null);
        }

        var team = text.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.StartsWith("TeamIdentifier=", StringComparison.Ordinal))?["TeamIdentifier=".Length..];
        return team is { Length: > 0 } and not "not set" ? ("Signed", $"TeamID={team}") : ("Signed", null);
    }

    /// <summary>Who signed the file and how, from codesign -dvvv's standard error.</summary>
    /// <remarks>
    /// Authority lines run from the leaf certificate up. The hardened runtime is a flag inside the CodeDirectory
    /// line ("flags=0x10000(runtime)"), not a line of its own, and "adhoc" appears there too -- so it is read from
    /// the flag names in the parentheses, never by searching the line.
    /// </remarks>
    public static CodesignDetails Details(string standardError)
    {
        string? identifier = null, team = null;
        var authorities = new List<string>();
        bool adHoc = false, runtime = false;
        foreach (var line in (standardError ?? string.Empty).Split('\n').Select(l => l.Trim()))
        {
            if (line.StartsWith("Identifier=", StringComparison.Ordinal))
            {
                identifier = line["Identifier=".Length..];
            }
            else if (line.StartsWith("TeamIdentifier=", StringComparison.Ordinal))
            {
                team = line["TeamIdentifier=".Length..] is { Length: > 0 } t and not "not set" ? t : null;
            }
            else if (line.StartsWith("Authority=", StringComparison.Ordinal))
            {
                authorities.Add(line["Authority=".Length..]);
            }
            else if (line == "Signature=adhoc")
            {
                adHoc = true;
            }
            else if (line.StartsWith("CodeDirectory ", StringComparison.Ordinal))
            {
                var flags = line.Split(' ').FirstOrDefault(token => token.StartsWith("flags=", StringComparison.Ordinal)) ?? string.Empty;
                var open = flags.IndexOf('(', StringComparison.Ordinal);
                var names = open < 0 ? [] : flags[(open + 1)..].TrimEnd(')').Split(',');
                runtime = names.Contains("runtime", StringComparer.Ordinal);
                adHoc |= names.Contains("adhoc", StringComparer.Ordinal);
            }
        }

        return new CodesignDetails(identifier, team, authorities, adHoc, runtime);
    }
}

/// <param name="Authorities">The certificate chain, leaf first; empty for an ad hoc signature.</param>
public sealed record CodesignDetails(string? Identifier, string? TeamId, IReadOnlyList<string> Authorities, bool AdHoc, bool HardenedRuntime)
{
}

/// <summary>pkgutil --file-info: the first receipt that names the file.</summary>
public static class PkgutilFileInfo
{
    public static (string? PackageId, string? Version) Parse(string text)
    {
        string? id = null, version = null;
        foreach (var line in (text ?? string.Empty).Split('\n').Select(l => l.Trim()))
        {
            if (id is null && line.StartsWith("pkgid: ", StringComparison.Ordinal))
            {
                id = line["pkgid: ".Length..].Trim();
            }
            else if (id is not null && version is null && line.StartsWith("pkg-version: ", StringComparison.Ordinal))
            {
                version = line["pkg-version: ".Length..].Trim();
            }
        }

        return (id, version);
    }
}
