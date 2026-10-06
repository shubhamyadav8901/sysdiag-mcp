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
/// section, which is the file that was mapped, wherever it has since been renamed to. That file is opened
/// by that name, held against writers and renames, and confirmed to be the mapped one
/// (<see cref="ModuleImageIdentity.WhyNotTheMappedFile"/>). Everything about the module is then read
/// through that one handle, so no later rename or replacement can split what was checked from what was
/// reported.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed class WindowsModuleImageSource : IModuleImageSource
{
    private const uint ProcessQueryInformation = 0x0400;

    private const uint GenericRead = 0x8000_0000;
    private const uint FileReadAttributes = 0x0080;
    private const uint FileShareRead = 0x1;
    private const uint FileShareAll = 0x7;
    private const uint OpenExisting = 3;
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
        GetFileInformationByHandleEx(handle, FileIdInfoClass, out var info, (uint)Marshal.SizeOf<FileIdInfo>())
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

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDeviceW(string deviceName, char[] targetPath, uint max);
}
