namespace WinDiag.Mcp.Diagnostics.Modules;

/// <summary>
/// The file behind one module's mapping, held open for as long as anything is read about the module.
/// </summary>
/// <remarks>
/// <para>Either <see cref="Held"/> is set, and it is the file the kernel names as mapped, on a path that
/// only SYSTEM, Administrators and TrustedInstaller could have changed
/// (<see cref="ModuleImageIdentity.WhyItsPathMayHaveMoved"/>) -- or <see cref="UnknownReason"/> says why
/// it is not. There is no third state in which a file is handed over with an identity that was not
/// settled: that state is the one that let a signed file at a module's path stand in for the unsigned
/// code actually running. Settled is a policy judgement, not a proof; the remarks on that method say
/// what it does not catch.</para>
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
    /// <returns>Null when nothing here says otherwise; otherwise why not.</returns>
    /// <remarks>
    /// <para>The held file cannot be renamed, and while it is open neither can the directories above it,
    /// so from the moment it is open its name is fixed. If the kernel then still names the mapping by that
    /// same name, the two are one file -- <em>provided the kernel's name is the mapped file's current
    /// name</em>, and it need not be. The kernel's name for a mapping is the name the file was opened
    /// under (Microsoft's <c>FLT_FILE_NAME_OPENED</c>: "the name that was used when the handle was opened
    /// to this file"). NTFS updates it when the file itself is renamed, but not when a directory above it
    /// is: CI's windows-latest run of
    /// <c>Never_verifies_the_file_put_at_a_loaded_dlls_path_after_its_directory_was_renamed_away</c> came
    /// back Valid, because the mapping still read as the old path and a signed copy had been put there.
    /// That hole is closed by <see cref="WhyItsPathMayHaveMoved"/>, not here. Each step here closes a way
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

    /// <summary>The sentence every refusal by <see cref="WhyItsPathMayHaveMoved"/> ends with.</summary>
    public const string OnlyAdminPathsTrusted =
        "Only a path that SYSTEM, Administrators and TrustedInstaller alone can change is trusted: rename a " +
        "directory on it away with the loaded file inside, and the kernel goes on naming the old path, " +
        "where another file can then be put";

    private const string SystemSid = "S-1-5-18";
    private const string AdministratorsSid = "S-1-5-32-544";
    private const string TrustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    private const byte AccessAllowedAce = 0x0;
    private const byte AccessDeniedAce = 0x1;
    private const byte AccessDeniedObjectAce = 0x6;
    private const byte AccessAllowedCallbackAce = 0x9;
    private const byte AccessDeniedCallbackAce = 0xA;
    private const byte AccessDeniedCallbackObjectAce = 0xC;
    private const byte InheritOnlyAce = 0x08;

    private const uint FileDeleteChild = 0x0000_0040;
    private const uint Delete = 0x0001_0000;
    private const uint WriteDac = 0x0004_0000;
    private const uint WriteOwner = 0x0008_0000;
    private const uint MaximumAllowed = 0x0200_0000;
    private const uint GenericAll = 0x1000_0000;

    /// <summary>
    /// Every directory above a local file, the volume root first: <c>C:\a\b\x.dll</c> gives
    /// <c>C:\</c>, <c>C:\a</c> and <c>C:\a\b</c>.
    /// </summary>
    /// <param name="localPath">A drive-letter path, as <see cref="LocalDosPath"/> returns.</param>
    public static IReadOnlyList<string> DirectoriesAbove(string localPath)
    {
        if (localPath.Length < 4 || localPath[1] != ':' || localPath[2] != '\\')
        {
            return [];
        }

        var directories = new List<string> { localPath[..3] };
        for (var i = 3; i < localPath.Length; i++)
        {
            if (localPath[i] == '\\')
            {
                directories.Add(localPath[..i]);
            }
        }

        return directories;
    }

    /// <summary>
    /// Whether anyone but SYSTEM, Administrators and TrustedInstaller could change a directory on the path
    /// the kernel names for a mapping -- and so could have made that name stale.
    /// </summary>
    /// <param name="chain">Each directory above the file, the volume root first (<see cref="DirectoriesAbove"/>).</param>
    /// <returns>Null when only those three can; otherwise why not, naming the first directory nearest the root.</returns>
    /// <remarks>
    /// <para>Why a policy and not a proof. Nothing in user mode names the file behind another process's
    /// image mapping except by the name it was opened under, which a directory rename leaves pointing at
    /// the old path (see <see cref="WhyNotTheMappedFile"/>). No API gives the mapped file's ID or a handle
    /// to it; <c>NtAreMappedFilesTheSame</c> compares views inside the calling process only. So "nothing
    /// was renamed" and "a directory was renamed away and a signed copy put at the old path" look the
    /// same from here, and the only thing left to judge is who <em>could</em> have done the second. This
    /// judges that on the directories as they are now. It is not a proof: a directory moved into place
    /// earlier, while its permissions or its parent's were looser, and then locked down, passes; anyone
    /// holding the restore or take-ownership privilege (Backup Operators, by default) can rename or take
    /// over any directory whatever its access list says; and an administrator can do anything, including
    /// load a driver that lies to every check.</para>
    /// <para>A directory is renamed by whoever has DELETE on it or FILE_DELETE_CHILD on its parent, and
    /// whoever owns it or has WRITE_DAC or WRITE_OWNER can grant themselves either. So on every directory
    /// the owner must be one of the three, the DACL must exist (a null DACL lets anyone do anything), and
    /// no allow entry for anyone else may grant WRITE_DAC, WRITE_OWNER, GENERIC_ALL, or:</para>
    /// <list type="bullet">
    /// <item>DELETE, except on the volume root, which cannot be renamed;</item>
    /// <item>FILE_DELETE_CHILD, except on the file's own directory, where it renames only the file -- and
    /// the kernel's name does follow a rename of the file itself, which is what the before-and-after
    /// comparison in <see cref="WhyNotTheMappedFile"/> catches.</item>
    /// </list>
    /// <para>Inherit-only entries are skipped because they grant nothing on the directory itself; deny
    /// entries because ignoring a deny can only make this stricter. An allow entry of a kind not read
    /// here, such as an object ACE, fails rather than being guessed at, as does a link or mount point on
    /// the path: then the directories that matter are not the ones named.</para>
    /// </remarks>
    public static string? WhyItsPathMayHaveMoved(IReadOnlyList<DirectoryGuard> chain)
    {
        if (chain.Count == 0)
        {
            return $"no directory on the path to its file could be examined. {OnlyAdminPathsTrusted}";
        }

        for (var i = 0; i < chain.Count; i++)
        {
            if (WhyChangeable(chain[i], isRoot: i == 0, holdsTheFile: i == chain.Count - 1) is { } problem)
            {
                return $"{chain[i].Path} {problem}. {OnlyAdminPathsTrusted}";
            }
        }

        return null;
    }

    private static string? WhyChangeable(DirectoryGuard directory, bool isRoot, bool holdsTheFile)
    {
        if (directory.UnreadableReason is { } unreadable)
        {
            return $"could not be examined ({unreadable})";
        }

        if (directory.IsReparsePoint)
        {
            return "is a link or mount point, so the directories that hold the file are not the ones named";
        }

        if (directory.Owner is not { } owner || !IsAdminOnly(owner))
        {
            return $"is owned by {directory.Owner ?? "no one"}, who can change who may rename it";
        }

        if (directory.Dacl is not { } dacl)
        {
            return "has no access list, so anyone may change it";
        }

        var dangerous = WriteDac | WriteOwner | GenericAll | MaximumAllowed
                        | (isRoot ? 0 : Delete)
                        | (holdsTheFile ? 0 : FileDeleteChild);

        foreach (var ace in dacl)
        {
            if (ace.Type is AccessDeniedAce or AccessDeniedObjectAce or AccessDeniedCallbackAce
                or AccessDeniedCallbackObjectAce)
            {
                continue;
            }

            if (ace.Type is not (AccessAllowedAce or AccessAllowedCallbackAce) || ace.Sid is not { } sid)
            {
                return $"has an access entry of a kind this server does not read (type 0x{ace.Type:X2})";
            }

            if ((ace.Flags & InheritOnlyAce) != 0 || IsAdminOnly(sid))
            {
                continue;
            }

            if ((ace.Mask & dangerous) is var granted and not 0)
            {
                return $"lets {sid} {Describe(granted)}";
            }
        }

        return null;
    }

    private static bool IsAdminOnly(string sid) =>
        sid.Equals(SystemSid, StringComparison.OrdinalIgnoreCase)
        || sid.Equals(AdministratorsSid, StringComparison.OrdinalIgnoreCase)
        || sid.Equals(TrustedInstallerSid, StringComparison.OrdinalIgnoreCase);

    private static string Describe(uint granted)
    {
        if ((granted & (GenericAll | MaximumAllowed)) != 0)
        {
            return "do anything to it";
        }

        var rights = new List<string>();
        if ((granted & Delete) != 0)
        {
            rights.Add("rename or delete it");
        }

        if ((granted & FileDeleteChild) != 0)
        {
            rights.Add("rename or delete what is in it");
        }

        if ((granted & WriteDac) != 0)
        {
            rights.Add("change its permissions");
        }

        if ((granted & WriteOwner) != 0)
        {
            rights.Add("take ownership of it");
        }

        return string.Join(", ", rights);
    }
}

/// <summary>One entry of a directory's access list, as the file system stores it.</summary>
/// <param name="Type">The ACE type: 0 for allow, 1 for deny, and so on.</param>
/// <param name="Flags">The ACE flags; 0x08 is INHERIT_ONLY_ACE.</param>
/// <param name="Mask">The access mask; zero when the type is not one whose mask is read.</param>
/// <param name="Sid">The trustee as a string SID; null when the type is not one whose trustee is read.</param>
internal readonly record struct DirectoryAce(byte Type, byte Flags, uint Mask, string? Sid);

/// <summary>What one directory on a module's path says about who can rename it, or change that.</summary>
/// <param name="Path">The directory, as a drive-letter path.</param>
/// <param name="UnreadableReason">Why its descriptor or attributes could not be read; null when they were.</param>
/// <param name="IsReparsePoint">Whether it is a junction, symbolic link or mount point.</param>
/// <param name="Owner">Its owner as a string SID.</param>
/// <param name="Dacl">Its access list; null when it has none or a null one, which both let anyone in.</param>
internal sealed record DirectoryGuard(
    string Path,
    string? UnreadableReason,
    bool IsReparsePoint,
    string? Owner,
    IReadOnlyList<DirectoryAce>? Dacl)
{
    public static DirectoryGuard Unreadable(string path, string reason) => new(path, reason, false, null, null);
}
