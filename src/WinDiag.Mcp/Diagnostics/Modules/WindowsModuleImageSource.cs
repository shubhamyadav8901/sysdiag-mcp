using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Diag.Mcp.Core;
using Microsoft.Win32.SafeHandles;

namespace WinDiag.Mcp.Diagnostics.Modules;

/// <summary>
/// Identifies the file behind each module mapped into a process from the kernel's record of the mapping,
/// not from the loader's path.
/// </summary>
/// <remarks>
/// <para>The path <c>Process.Modules</c> reports is the loader's, kept in the process's own memory, and it
/// does not follow a rename: rename a loaded DLL away and put a signed copy at its path, and every check
/// made by that path checks the copy. Comparing PE headers between the mapping and the file did not fix
/// that -- every field compared is the DLL author's to choose, so an unsigned DLL built with a Microsoft
/// DLL's stamp, size and checksum matched its signed stand-in exactly.</para>
/// <para><c>GetMappedFileName</c> asks the kernel for the name of the file object behind the image
/// section. That is the name the file was opened under, which follows a rename of the file itself but not
/// of a directory above it -- so a directory renamed away with the loaded DLL inside, and a signed copy
/// put at the old path, leaves the kernel naming the copy. No user-mode API names the mapped file any
/// other way, so the name is trusted only on a path that SYSTEM, Administrators and TrustedInstaller
/// alone could have changed (<see cref="ModuleImageIdentity.WhyItsPathMayHaveMoved"/>): a policy
/// judgement, not a proof. The file is opened by that name, held against writers and renames, and
/// confirmed to be the one the kernel still names (<see cref="ModuleImageIdentity.WhyNotTheMappedFile"/>).
/// Everything about the module is then read through that one handle, so no later rename or replacement
/// can split what was checked from what was reported.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed class WindowsModuleImageSource : IModuleImageSource
{
    private const uint ProcessQueryInformation = 0x0400;

    private const uint GenericRead = 0x8000_0000;
    private const uint ReadControl = 0x0002_0000;
    private const uint FileReadAttributes = 0x0080;
    private const uint FileShareRead = 0x1;
    private const uint FileShareAll = 0x7;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x0200_0000;
    private const uint FileFlagOpenReparsePoint = 0x0020_0000;
    private const uint FileAttributeDirectory = 0x10;
    private const uint FileAttributeReparsePoint = 0x400;
    private const int FileAttributeTagInfoClass = 9;
    private const int SeFileObject = 1;
    private const uint OwnerSecurityInformation = 0x1;
    private const uint DaclSecurityInformation = 0x4;
    private const uint FileNameOpened = 0x8;
    private const uint VolumeNameNt = 0x2;
    private const int FileIdInfoClass = 18;

    // The kernel's names are NT paths, which may run to 32K characters; one buffer per listing, reused.
    private readonly char[] _name = new char[32_768];
    private readonly SafeProcessHandle? _process;
    private readonly string? _processFailure;
    private readonly IReadOnlyList<(char Letter, string Device)> _localDrives;

    private WindowsModuleImageSource(SafeProcessHandle? process, string? processFailure)
    {
        _process = process;
        _processFailure = processFailure;
        _localDrives = LocalDrives();
    }

    /// <remarks>
    /// Its own handle, with only what <c>GetMappedFileName</c> documents it needs, rather than
    /// <c>Process.Handle</c>'s far broader mask. Failing to open it costs every module its identity, and
    /// each then says so rather than falling back to the path.
    /// </remarks>
    public static WindowsModuleImageSource Open(int processId)
    {
        var handle = OpenProcess(ProcessQueryInformation, false, processId);
        if (!handle.IsInvalid)
        {
            return new WindowsModuleImageSource(handle, null);
        }

        var error = Marshal.GetLastPInvokeError();
        handle.Dispose();
        return new WindowsModuleImageSource(null,
            $"this server could not open the process to ask the kernel which file backs each module " +
            $"({Describe(error)})");
    }

    public ModuleImageFile Open(string listedPath, ulong baseAddress)
    {
        if (_process is null)
        {
            return ModuleImageFile.Unknown(_processFailure!);
        }

        var before = MappedFileName(baseAddress, out var nameError);
        if (before is null)
        {
            return ModuleImageFile.Unknown(
                $"the kernel did not name the file mapped at 0x{baseAddress:X} ({Describe(nameError)})");
        }

        var local = ModuleImageIdentity.LocalDosPath(before, _localDrives);
        if (local is null)
        {
            return ModuleImageFile.Unknown(
                $"its file, {before}, is not on a local drive with a letter. A network share is not opened: " +
                "that would sign this server in to whoever serves it, and the share's server could change " +
                "the file under the mapping anyway");
        }

        // GENERIC_READ shared for reading only: nobody can write, rename or delete the file while it is
        // held, and an open of a file someone else already holds for writing or deleting fails rather than
        // reading it mid-change.
        var handle = CreateFileW(@"\\?\" + local, GenericRead, FileShareRead, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            return ModuleImageFile.Unknown(
                $"its file, {local}, could not be held open against changes ({Describe(error)})");
        }

        try
        {
            var mappedAfter = MappedFileName(baseAddress, out _);
            var openedAs = FinalNtName(handle);

            if (ModuleImageIdentity.WhyNotTheMappedFile(before, openedAs, mappedAfter) is { } reason)
            {
                handle.Dispose();
                return ModuleImageFile.Unknown(reason);
            }

            // Judged while the file is held: held without delete sharing, it pins every directory above
            // it against renames (A_file_held_as_a_module_file_is_held_cannot_be_renamed_and_neither_can_its_directory),
            // so the directories examined are the ones the file was just opened through.
            var chain = ModuleImageIdentity.DirectoriesAbove(local).Select(Guard).ToList();
            if (ModuleImageIdentity.WhyItsPathMayHaveMoved(chain) is { } moved)
            {
                handle.Dispose();
                return ModuleImageFile.Unknown(moved);
            }

            var listed = ListedPathIsOtherFile(listedPath, Identity(handle));

            // Unbuffered: the signature check reads through the same handle natively, behind its back.
            return ModuleImageFile.Identified(new FileStream(handle, FileAccess.Read, 0), local, listed);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public void Dispose() => _process?.Dispose();

    /// <summary>Whether the listed path now names a different file, by volume and file ID.</summary>
    /// <remarks>
    /// By ID rather than by name, so a hard link or a short-name spelling of the same file is not called a
    /// replacement. Attributes-only, so a file this account may not read can still be compared. A network
    /// or device path is never opened, for the sign-in reason <see cref="Open(string, ulong)"/> gives; the
    /// listed path is the process's to write.
    /// </remarks>
    private static bool? ListedPathIsOtherFile(string listedPath, FileIdentity? image)
    {
        // Not fully qualified, it would be resolved against this server's own working directory and
        // compared with whatever happens to be there.
        if (string.IsNullOrWhiteSpace(listedPath)
            || !Path.IsPathFullyQualified(listedPath)
            || NetworkPath.IsNetworkOrDevice(listedPath))
        {
            return null;
        }

        using var listed = CreateFileW(listedPath, FileReadAttributes, FileShareAll, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (listed.IsInvalid)
        {
            return ModuleImageIdentity.ListedPathIsOtherFile(Marshal.GetLastPInvokeError(), null, image);
        }

        return ModuleImageIdentity.ListedPathIsOtherFile(null, Identity(listed), image);
    }

    /// <summary>Who owns one directory, who may do what to it, and whether it is a link.</summary>
    /// <remarks>
    /// Through one handle, opened with <c>FILE_FLAG_OPEN_REPARSE_POINT</c> so a junction or link at that
    /// name is examined itself rather than followed, and never reopened by path. Every failure is an
    /// unreadable directory, which fails the policy closed: a descriptor this server cannot read is not
    /// evidence that only administrators can change it.
    /// </remarks>
    private static DirectoryGuard Guard(string directory)
    {
        using var handle = CreateFileW(@"\\?\" + directory, ReadControl | FileReadAttributes, FileShareAll,
            IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            return DirectoryGuard.Unreadable(directory, Describe(Marshal.GetLastPInvokeError()));
        }

        if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass, out FileAttributeTagInfo tag, (uint)Marshal.SizeOf<FileAttributeTagInfo>()))
        {
            return DirectoryGuard.Unreadable(directory, Describe(Marshal.GetLastPInvokeError()));
        }

        if ((tag.FileAttributes & FileAttributeDirectory) == 0)
        {
            return DirectoryGuard.Unreadable(directory, "it is not a directory");
        }

        var error = GetSecurityInfo(handle, SeFileObject, OwnerSecurityInformation | DaclSecurityInformation,
            out var owner, out _, out var dacl, out _, out var descriptor);
        if (error != 0)
        {
            return DirectoryGuard.Unreadable(directory, Describe((int)error));
        }

        try
        {
            if (owner == IntPtr.Zero || SidString(owner) is not { } ownerSid)
            {
                return DirectoryGuard.Unreadable(directory, "its owner could not be read");
            }

            // No DACL pointer is a descriptor with no DACL or a null one, and Windows grants everyone full
            // access to both ("Null DACLs and Empty DACLs"); the policy refuses null for exactly that.
            List<DirectoryAce>? entries = null;
            if (dacl != IntPtr.Zero)
            {
                entries = [];
                var count = (ushort)Marshal.ReadInt16(dacl, 4); // ACL.AceCount
                for (var i = 0; i < count; i++)
                {
                    if (!GetAce(dacl, (uint)i, out var ace))
                    {
                        return DirectoryGuard.Unreadable(directory, Describe(Marshal.GetLastPInvokeError()));
                    }

                    var type = Marshal.ReadByte(ace, 0);
                    var flags = Marshal.ReadByte(ace, 1);

                    // ACCESS_ALLOWED, ACCESS_DENIED and their callback forms share one layout: the
                    // ACE_HEADER, the mask, then the SID. Any other type is passed on unread, and an
                    // unread allow fails the policy.
                    if (type is 0x0 or 0x1 or 0x9 or 0xA)
                    {
                        if (SidString(ace + 8) is not { } sid)
                        {
                            return DirectoryGuard.Unreadable(directory, "an access entry's trustee could not be read");
                        }

                        entries.Add(new DirectoryAce(type, flags, (uint)Marshal.ReadInt32(ace, 4), sid));
                    }
                    else
                    {
                        entries.Add(new DirectoryAce(type, flags, 0, null));
                    }
                }
            }

            return new DirectoryGuard(directory, null, (tag.FileAttributes & FileAttributeReparsePoint) != 0,
                ownerSid, entries);
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    private static string? SidString(IntPtr sid)
    {
        if (!ConvertSidToStringSidW(sid, out var text))
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUni(text);
        }
        finally
        {
            LocalFree(text);
        }
    }

    private string? MappedFileName(ulong baseAddress, out int error)
    {
        var length = K32GetMappedFileNameW(_process!, (IntPtr)(long)baseAddress, _name, (uint)_name.Length);
        error = length == 0 ? Marshal.GetLastPInvokeError() : 0;

        // A full buffer is a truncated name, and half a name is not one to open.
        return length == 0 || length >= _name.Length - 1 ? null : new string(_name, 0, (int)length);
    }

    private string? FinalNtName(SafeFileHandle handle)
    {
        var length = GetFinalPathNameByHandleW(handle, _name, (uint)_name.Length, FileNameOpened | VolumeNameNt);
        return length == 0 || length >= _name.Length ? null : new string(_name, 0, (int)length);
    }

    private static FileIdentity? Identity(SafeFileHandle handle) =>
        GetFileInformationByHandleEx(handle, FileIdInfoClass, out FileIdInfo info, (uint)Marshal.SizeOf<FileIdInfo>())
            ? new FileIdentity(info.VolumeSerialNumber, new UInt128(info.FileIdHigh, info.FileIdLow))
            : null;

    /// <summary>Each drive letter on a local disk, with the kernel device it maps to.</summary>
    /// <remarks>
    /// Read once per listing, from this server's own view of the drive letters -- a per-user mapping made
    /// by the user who owns the target process is not in it. Network and unknown drive types are left
    /// out, which is what keeps a share off the list of places this server will open.
    /// </remarks>
    private static IReadOnlyList<(char Letter, string Device)> LocalDrives()
    {
        var drives = new List<(char, string)>();
        var target = new char[1024];

        for (var letter = 'A'; letter <= 'Z'; letter++)
        {
            if (NetworkPath.DriveTypeOf(letter) is not (DriveType.Fixed or DriveType.Removable
                or DriveType.CDRom or DriveType.Ram))
            {
                continue;
            }

            var length = QueryDosDeviceW($"{letter}:", target, (uint)target.Length);
            if (length == 0)
            {
                continue;
            }

            // The first of the null-separated targets is the current one.
            var end = Array.IndexOf(target, '\0', 0, (int)length);
            var device = new string(target, 0, end >= 0 ? end : (int)length);
            if (device.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            {
                drives.Add((letter, device));
            }
        }

        return drives;
    }

    private static string Describe(int error) =>
        $"error {error.ToString(CultureInfo.InvariantCulture)}: {new Win32Exception(error).Message}";

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo
    {
        public ulong VolumeSerialNumber;
        public ulong FileIdLow;
        public ulong FileIdHigh;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint K32GetMappedFileNameW(SafeProcessHandle process, IntPtr address, char[] fileName, uint size);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(
        string fileName, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, char[] path, uint size, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file, int informationClass, out FileIdInfo information, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file, int informationClass, out FileAttributeTagInfo information, uint size);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(
        SafeFileHandle handle, int objectType, uint securityInfo, out IntPtr owner, out IntPtr group,
        out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetAce(IntPtr acl, uint index, out IntPtr ace);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr text);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDeviceW(string deviceName, char[] targetPath, uint max);
}
