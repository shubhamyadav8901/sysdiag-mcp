namespace WinDiag.Mcp.Diagnostics.Modules;

/// <summary>
/// The file behind one module's mapping, held open for as long as anything is read about the module.
/// </summary>
/// <remarks>
/// <para>Either <see cref="Held"/> is set, and it is the very file the process mapped -- proven, not
/// guessed from a path -- or <see cref="UnknownReason"/> says why it could not be. There is no third state
/// in which a file is handed over with an identity that was not settled: that state is the one that let a
/// signed file at a module's path stand in for the unsigned code actually running.</para>
/// <para>Held without write or delete sharing, so for as long as this lives the file cannot be written,
/// renamed or deleted, and a path-only API given <see cref="HeldPath"/> reads the same bytes.</para>
/// </remarks>
internal sealed class ModuleImageFile : IDisposable
{
    private ModuleImageFile(FileStream? held, string? heldPath, string? unknownReason, bool? listedPathIsOtherFile)
    {
        Held = held;
        HeldPath = heldPath;
        UnknownReason = unknownReason;
        ListedPathIsOtherFile = listedPathIsOtherFile;
    }

    /// <summary>The loaded image's file, held against writers and renames. Null when it was not identified.</summary>
    public FileStream? Held { get; }

    /// <summary>A local path to <see cref="Held"/>, for the APIs that will only take a path.</summary>
    public string? HeldPath { get; }

    /// <summary>Why the loaded image's file could not be identified; null when it was.</summary>
    public string? UnknownReason { get; }

    /// <summary>
    /// Whether the module's listed path names some other file than the loaded image's, or nothing at all.
    /// Null when that could not be settled.
    /// </summary>
    public bool? ListedPathIsOtherFile { get; }

    public static ModuleImageFile Identified(FileStream held, string heldPath, bool? listedPathIsOtherFile) =>
        new(held, heldPath, null, listedPathIsOtherFile);

    public static ModuleImageFile Unknown(string reason) => new(null, null, reason, null);

    public void Dispose() => Held?.Dispose();
}

/// <summary>Finds and holds the file behind each module mapped into one process.</summary>
internal interface IModuleImageSource : IDisposable
{
    /// <param name="listedPath">The path the loader recorded for the module, compared with what is found.</param>
    /// <param name="baseAddress">Where the module is mapped in the target process.</param>
    ModuleImageFile Open(string listedPath, ulong baseAddress);
}

/// <summary>A file's identity on its volume: the volume serial and the 128-bit file ID.</summary>
internal readonly record struct FileIdentity(ulong VolumeSerial, UInt128 FileId)
{
    /// <summary>
    /// False for an all-zero ID, which some file systems and redirectors report for every file -- two
    /// such "identities" agreeing would prove nothing.
    /// </summary>
    public bool IsKnown => FileId != UInt128.Zero;
}

/// <summary>
/// The decisions behind identifying a module's file, apart from the calls that gather what they decide on,
/// so each can be pinned without a process.
/// </summary>
internal static class ModuleImageIdentity
{
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;

    /// <summary>
    /// Whether the file held open is the one the process mapped, from the kernel's name for the mapping
    /// before the open, the name the held file was opened under, and the mapping's name again after.
    /// </summary>
    /// <returns>Null when it is proven; otherwise why not.</returns>
    /// <remarks>
    /// <para>The held file cannot be renamed, and while it is open neither can the directories above it,
    /// so from the moment it is open its name is fixed. If the kernel then still names the mapping by that
    /// same name, the two are one file: two files cannot have one name at once. Each step closes a way
    /// round the one before it:</para>
    /// <list type="bullet">
    /// <item>The name read back from the held file must be the name it was opened by. Otherwise a link or
    /// junction swapped in on the way led the open to another file.</item>
    /// <item>The mapping must still carry that name afterwards, compared exactly. Otherwise the mapped
    /// file was renamed away and another put in its place between asking and opening -- the window the
    /// old path-by-path checks left open for the whole length of the list. Exactly, because in a
    /// case-sensitive directory <c>x.dll</c> and <c>X.DLL</c> are two files.</item>
    /// </list>
    /// <para>The opened name is compared ignoring case only because it is the file system's echo of a
    /// string this server supplied, whose case some file systems normalise; the open itself was made with
    /// that exact string, so it cannot have reached a differently-cased sibling.</para>
    /// </remarks>
    public static string? WhyNotTheMappedFile(string mappedBefore, string? openedAs, string? mappedAfter)
    {
        if (openedAs is null)
        {
            return $"the file opened at {mappedBefore} could not report its own name, so it could not be " +
                   "shown to be the mapped file";
        }

        if (!string.Equals(openedAs, mappedBefore, StringComparison.OrdinalIgnoreCase))
        {
            return $"opening the mapped file's name, {mappedBefore}, reached {openedAs} instead -- a link or " +
                   "junction on the way, or the path changed while it was being opened";
        }

        if (mappedAfter is null)
        {
            return "the kernel stopped naming the module's mapping while it was being checked -- it may " +
                   "have just been unloaded";
        }

        if (!string.Equals(mappedAfter, mappedBefore, StringComparison.Ordinal))
        {
            return $"the mapped file was renamed while it was being checked, from {mappedBefore} to " +
                   $"{mappedAfter}, so the file opened at its old name is not proven to be it";
        }

        return null;
    }

    /// <summary>
    /// Whether the module's listed path names some other file than the loaded image's, from what opening
    /// that path found.
    /// </summary>
    /// <param name="openError">The Win32 error opening the listed path failed with; null when it opened.</param>
    /// <param name="listed">The identity of the file the listed path opened, when it did.</param>
    /// <param name="image">The identity of the loaded image's file.</param>
    /// <remarks>
    /// Only "not found" means the path is empty. Access denied, a sharing violation or anything else is
    /// unknown, not "replaced": a file this server may not open is not evidence that it changed, and
    /// calling it replaced would send the reader after a tampering that never happened.
    /// </remarks>
    public static bool? ListedPathIsOtherFile(int? openError, FileIdentity? listed, FileIdentity? image)
    {
        if (openError is ErrorFileNotFound or ErrorPathNotFound)
        {
            return true;
        }

        if (openError is not null
            || listed is not { IsKnown: true } listedId
            || image is not { IsKnown: true } imageId)
        {
            return null;
        }

        return listedId != imageId;
    }

    /// <summary>
    /// The drive-letter path for a kernel file name on one of this machine's local drives, or null when
    /// it is on none of them.
    /// </summary>
    /// <param name="ntName">The kernel's name for a file, e.g. <c>\Device\HarddiskVolume3\Windows\x.dll</c>.</param>
    /// <param name="localDrives">Each local drive letter with the device it maps to.</param>
    /// <remarks>
    /// <para>An allowlist of local drives rather than a list of network devices to avoid. Opening a file
    /// on a share makes this server -- as LocalSystem, the machine account -- sign in to whoever serves it,
    /// which a user could aim anywhere by loading a DLL from a share of their own. And a share's server can
    /// change the file under a mapping, so it could not be pinned anyway. A volume with no drive letter
    /// is refused as well: rarer, and costing only that module its verdict.</para>
    /// <para>The device must be followed by a separator, so <c>\Device\HarddiskVolume1</c> does not claim
    /// <c>\Device\HarddiskVolume10\...</c>.</para>
    /// </remarks>
    public static string? LocalDosPath(string ntName, IReadOnlyList<(char Letter, string Device)> localDrives)
    {
        foreach (var (letter, device) in localDrives)
        {
            if (ntName.Length > device.Length + 1
                && ntName.StartsWith(device, StringComparison.OrdinalIgnoreCase)
                && ntName[device.Length] == '\\')
            {
                return $"{letter}:{ntName[device.Length..]}";
            }
        }

        return null;
    }
}
