using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace WinDiag.Mcp.Hosting;

/// <summary>
/// Files and directories opened as themselves -- never through a link -- listed and opened relative to a
/// directory already held, and their security read and written through that same handle.
/// </summary>
/// <remarks>
/// <para>Everything .NET offers for a directory's ACL or its contents works by path, and a path is resolved
/// again on every call. Judging an item by one call and writing its ACL, or listing what is in it, with
/// another leaves a moment in which whoever can still write it -- that is why it is being taken over --
/// turns an empty directory into a mount point, and the write, and everything after it, lands on wherever
/// that points. Through one handle opened without following a link, the object judged is the object
/// written; and a child opened by its bare name relative to its parent's handle is looked up in that
/// directory itself, whatever its path now leads to.</para>
/// <para>The security is written with SetKernelObjectSecurity, which sets that one object's descriptor and
/// nothing else. SetSecurityInfo -- what .NET's own handle-based write calls -- also carries inheritable ACEs
/// down to every existing child, before any child has been looked at: a hard link a user added a moment
/// earlier would have its other name's file, a System32 binary say, rewritten before it could be refused.
/// Callers write each child's descriptor themselves, inherited ACEs included, after judging it.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
internal static class FileObjects
{
    internal const uint ReadControl = 0x00020000;
    internal const uint WriteDac = 0x00040000;
    internal const uint WriteOwner = 0x00080000;
    internal const uint ListDirectory = 0x0001;
    internal const uint ReadAttributes = 0x0080;
    internal const uint Synchronize = 0x00100000;

    // Data deduplication and Windows Overlay Filter (compact /exe) compression. Both keep a file's own data
    // and name; nothing about them leads anywhere else.
    internal const uint DedupTag = 0x80000013;
    internal const uint WofTag = 0x80000017;

    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const int ErrorAccessDenied = 5;
    private const int ErrorNoMoreFiles = 18;
    private const int ErrorAlreadyExists = 183;
    private const uint BackupSemantics = 0x02000000;
    private const uint OpenReparsePoint = 0x00200000;
    private const int FileAttributeTagInfoClass = 9;
    private const int FileFullDirectoryInfoClass = 14;
    private const int FileFullDirectoryRestartInfoClass = 15;

    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint ProtectedDaclSecurityInformation = 0x80000000;
    private const uint UnprotectedDaclSecurityInformation = 0x20000000;

    // NtOpenFile's spelling of OpenReparsePoint and BackupSemantics, and the synchronous I/O a directory
    // listing through the handle needs.
    private const uint FileOpenReparsePoint = 0x00200000;
    private const uint FileOpenForBackupIntent = 0x00004000;
    private const uint FileSynchronousIoNonAlert = 0x00000020;

    private const int StatusObjectNameNotFound = unchecked((int)0xC0000034);
    private const int StatusObjectPathNotFound = unchecked((int)0xC000003A);
    private const int StatusDeletePending = unchecked((int)0xC0000056);

    // FILE_FULL_DIR_INFO: where each entry keeps the offset of the next, its name's length in bytes, and its name.
    private const int NextEntryOffsetAt = 0;
    private const int FileNameLengthAt = 60;
    private const int FileNameAt = 68;

    /// <summary>What an opened file or directory is.</summary>
    internal readonly record struct Node(uint Attributes, uint Links, uint ReparseTag)
    {
        public bool IsDirectory => (Attributes & (uint)FileAttributes.Directory) != 0;

        public bool IsLink => FileObjects.IsLink(Attributes, ReparseTag);

        /// <summary>A file with another name elsewhere on the volume, which shares its ACL.</summary>
        public bool IsHardLink => !IsDirectory && Links > 1;
    }

    /// <summary>Whether an item with these attributes and reparse tag leads somewhere other than itself.</summary>
    /// <remarks>
    /// A directory that is a reparse point of any kind is one: a junction, a symbolic link, a mounted volume or
    /// a cloud placeholder, all of which present something other than a folder an administrator controls. A
    /// file is one unless its tag is deduplication or compression, which a Windows Server data volume or
    /// <c>compact /exe</c> gives files that are entirely ordinary -- refusing those took dumps and the server
    /// binary for links. Any tag not known to be harmless counts.
    /// </remarks>
    internal static bool IsLink(uint attributes, uint reparseTag) =>
        (attributes & (uint)FileAttributes.ReparsePoint) != 0
        && ((attributes & (uint)FileAttributes.Directory) != 0 || reparseTag is not (DedupTag or WofTag));

    /// <summary>A full path in the <c>\\?\</c> form, which CreateFileW and CreateDirectoryW take past MAX_PATH.</summary>
    /// <remarks>
    /// .NET adds the prefix itself, so a tree it lists can be deeper than 260 characters; a raw call without
    /// it fails such a path as not found, and an item taken for gone is an item never judged.
    /// </remarks>
    internal static string Extended(string fullPath) =>
        fullPath.StartsWith(@"\\?\", StringComparison.Ordinal) || fullPath.StartsWith(@"\\.\", StringComparison.Ordinal)
            ? fullPath
            : fullPath.StartsWith(@"\\", StringComparison.Ordinal)
                ? @"\\?\UNC\" + fullPath[2..]
                : @"\\?\" + fullPath;

    /// <summary>Opens <paramref name="fullPath"/> itself, never what it links to; null when nothing is there.</summary>
    /// <exception cref="UnauthorizedAccessException">This account may not open it with <paramref name="access"/>.</exception>
    public static SafeFileHandle? Open(string fullPath, uint access, FileShare share)
    {
        var handle = CreateFile(Extended(fullPath), access, share, IntPtr.Zero, FileMode.Open, BackupSemantics | OpenReparsePoint, IntPtr.Zero);
        if (!handle.IsInvalid)
        {
            return handle;
        }

        var error = Marshal.GetLastPInvokeError();
        handle.Dispose();
        return error is ErrorFileNotFound or ErrorPathNotFound ? null : throw Failure(fullPath, error);
    }

    /// <summary>
    /// Opens the entry called <paramref name="name"/> in the directory <paramref name="directory"/> has open,
    /// never what it links to; with an empty name, the object <paramref name="directory"/> has open, again.
    /// Null when nothing is there.
    /// </summary>
    /// <param name="directory">A handle on a directory, or on any object when <paramref name="name"/> is empty.</param>
    /// <param name="name">One name as the directory lists it, with no separator in it.</param>
    /// <param name="access">The rights wanted; <see cref="Synchronize"/> is added, for synchronous listing.</param>
    /// <param name="share">What others may do with it meanwhile.</param>
    /// <param name="path">The item's path, for messages only: nothing here resolves it.</param>
    /// <remarks>
    /// Relative to the handle, the name is looked up in the very directory that was judged, so neither a
    /// directory above it being renamed nor a link put where it used to be changes what is opened. An empty
    /// name opens the same object anew, with other rights -- the listing right on a directory first opened
    /// without it, which would otherwise mean naming it, and resolving it, again.
    /// </remarks>
    /// <exception cref="UnauthorizedAccessException">This account may not open it with <paramref name="access"/>.</exception>
    public static SafeFileHandle? OpenChild(SafeFileHandle directory, string name, uint access, FileShare share, string path)
    {
        if (name.Contains('\\', StringComparison.Ordinal) || name.Contains('/', StringComparison.Ordinal))
        {
            throw new ArgumentException($"'{name}' is not a single name.", nameof(name));
        }

        var added = false;
        var buffer = Marshal.StringToHGlobalUni(name);
        var unicode = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
        try
        {
            directory.DangerousAddRef(ref added);
            Marshal.StructureToPtr(
                new UnicodeString { Length = (ushort)(name.Length * 2), MaximumLength = (ushort)((name.Length + 1) * 2), Buffer = buffer },
                unicode, fDeleteOld: false);

            var attributes = new ObjectAttributes
            {
                Length = Marshal.SizeOf<ObjectAttributes>(),
                RootDirectory = directory.DangerousGetHandle(),
                ObjectName = unicode
            };

            var status = NtOpenFile(
                out var opened, access | Synchronize, ref attributes, out _, (uint)share,
                FileOpenReparsePoint | FileOpenForBackupIntent | FileSynchronousIoNonAlert);

            if (status >= 0)
            {
                return new SafeFileHandle(opened, ownsHandle: true);
            }

            return status is StatusObjectNameNotFound or StatusObjectPathNotFound or StatusDeletePending
                ? null
                : throw Failure(path, RtlNtStatusToDosError(status));
        }
        finally
        {
            if (added)
            {
                directory.DangerousRelease();
            }

            Marshal.FreeHGlobal(unicode);
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>The names in the directory <paramref name="directory"/> has open, hidden and system ones included.</summary>
    /// <remarks>
    /// Read through the handle, so it is that directory's own entries whatever its path leads to now. The
    /// handle needs <see cref="ListDirectory"/> and synchronous I/O, which <see cref="OpenChild"/> and
    /// <see cref="Open"/> both give it.
    /// </remarks>
    public static List<string> Children(SafeFileHandle directory, string path)
    {
        const int size = 64 * 1024;
        var native = Marshal.AllocHGlobal(size);
        try
        {
            var names = new List<string>();
            var managed = new byte[size];
            var informationClass = FileFullDirectoryRestartInfoClass;
            while (GetFileInformationByHandleEx(directory, informationClass, native, size))
            {
                Marshal.Copy(native, managed, 0, size);
                names.AddRange(EntryNames(managed));
                informationClass = FileFullDirectoryInfoClass;
            }

            var error = Marshal.GetLastPInvokeError();
            return error == ErrorNoMoreFiles ? names : throw Failure(path, error);
        }
        finally
        {
            Marshal.FreeHGlobal(native);
        }
    }

    /// <summary>The names in one buffer of FILE_FULL_DIR_INFO entries, without "." and "..".</summary>
    internal static List<string> EntryNames(byte[] buffer)
    {
        var names = new List<string>();
        for (var offset = 0; ; )
        {
            var next = BitConverter.ToInt32(buffer, offset + NextEntryOffsetAt);
            var length = BitConverter.ToInt32(buffer, offset + FileNameLengthAt);
            var name = Encoding.Unicode.GetString(buffer, offset + FileNameAt, length);
            if (name is not ("." or ".."))
            {
                names.Add(name);
            }

            if (next == 0)
            {
                return names;
            }

            offset += next;
        }
    }

    /// <summary>
    /// Creates the directory <paramref name="fullPath"/> with <paramref name="descriptor"/> as its security from
    /// the start; false, changing nothing, when something is already there.
    /// </summary>
    /// <remarks>
    /// .NET's <c>CreateDirectory(DirectorySecurity, path)</c> returns quietly when the directory exists, so a
    /// directory someone made a moment before -- theirs, with whatever ACL they chose -- would pass as the one
    /// it was asked to create. This says which it was.
    /// </remarks>
    public static bool CreateDirectory(string fullPath, byte[] descriptor)
    {
        var pinned = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = pinned.AddrOfPinnedObject()
            };

            if (CreateDirectoryW(Extended(fullPath), ref attributes))
            {
                return true;
            }

            var error = Marshal.GetLastPInvokeError();
            return error == ErrorAlreadyExists ? false : throw Failure(fullPath, error);
        }
        finally
        {
            pinned.Free();
        }
    }

    /// <summary>The attributes, link count and reparse tag of what <paramref name="handle"/> has open.</summary>
    public static Node Inspect(SafeFileHandle handle, string path)
    {
        if (!GetFileInformationByHandle(handle, out var info))
        {
            throw Failure(path, Marshal.GetLastPInvokeError());
        }

        uint tag = 0;
        if ((info.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0)
        {
            if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass, out var tagInfo, (uint)Marshal.SizeOf<FileAttributeTagInfo>()))
            {
                throw Failure(path, Marshal.GetLastPInvokeError());
            }

            tag = tagInfo.ReparseTag;
        }

        return new Node(info.FileAttributes, info.NumberOfLinks, tag);
    }

    /// <summary>The owner and DACL of what <paramref name="handle"/> has open, which needs <see cref="ReadControl"/>.</summary>
    /// <remarks>
    /// Handed back as the runtime's own DirectorySecurity or FileSecurity, whose rule factory takes every ACE
    /// as stored -- generic rights included, which CREATOR OWNER's inherit-only ACEs carry and the public
    /// FileSystemAccessRule constructors refuse.
    /// </remarks>
    public static FileSystemSecurity ReadAcl(SafeFileHandle handle, bool isDirectory)
    {
        var raw = new HandleSecurity(isDirectory, handle);
        FileSystemSecurity acl = isDirectory ? new DirectorySecurity() : new FileSecurity();
        acl.SetSecurityDescriptorBinaryForm(raw.GetSecurityDescriptorBinaryForm(), AccessControlSections.Access | AccessControlSections.Owner);
        return acl;
    }

    /// <summary>
    /// Writes the DACL of the self-relative <paramref name="descriptor"/>, and its owner when
    /// <paramref name="withOwner"/>, to what <paramref name="handle"/> has open, and to nothing else.
    /// </summary>
    /// <remarks>
    /// <para>Needs <see cref="WriteDac"/>, and <see cref="WriteOwner"/> for the owner. Which ACEs count as
    /// inherited is what the descriptor says: nothing is computed from the parent and nothing is carried to
    /// children. <paramref name="protectedDacl"/> is said both in the descriptor's control bits and in the
    /// call, so neither layer is left to infer it.</para>
    /// <para>Microsoft's documentation steers file objects away from SetKernelObjectSecurity towards
    /// SetSecurityInfo precisely because it does not propagate. Here that is the point.</para>
    /// </remarks>
    public static void WriteSecurity(SafeFileHandle handle, byte[] descriptor, bool withOwner, bool protectedDacl, string path)
    {
        var information = DaclSecurityInformation
                          | (withOwner ? OwnerSecurityInformation : 0)
                          | (protectedDacl ? ProtectedDaclSecurityInformation : UnprotectedDaclSecurityInformation);
        if (!SetKernelObjectSecurity(handle, information, descriptor))
        {
            throw Failure(path, Marshal.GetLastPInvokeError());
        }
    }

    private static Exception Failure(string path, int error)
    {
        var message = $"{new Win32Exception(error).Message} ({path})";
        return error switch
        {
            ErrorFileNotFound => new FileNotFoundException(message, path),
            ErrorPathNotFound => new DirectoryNotFoundException(message),
            ErrorAccessDenied => new UnauthorizedAccessException(message),
            _ => new IOException(message, unchecked((int)0x80070000) | error)
        };
    }

    /// <summary>A file object's security read through a handle, which DirectorySecurity cannot do.</summary>
    /// <remarks>
    /// The protected constructor of <see cref="NativeObjectSecurity"/> is the runtime's own handle-based
    /// read, so nothing here re-implements how a security descriptor is marshalled.
    /// </remarks>
    private sealed class HandleSecurity : NativeObjectSecurity
    {
        public HandleSecurity(bool isDirectory, SafeHandle handle)
            : base(isDirectory, ResourceType.FileObject, handle, AccessControlSections.Access | AccessControlSections.Owner)
        {
        }

        public override Type AccessRightType => typeof(FileSystemRights);

        public override Type AccessRuleType => typeof(FileSystemAccessRule);

        public override Type AuditRuleType => typeof(FileSystemAuditRule);

        // Never asked for: rules are read from the DirectorySecurity or FileSecurity ReadAcl copies this into.
        public override AccessRule AccessRuleFactory(
            System.Security.Principal.IdentityReference identityReference, int accessMask, bool isInherited,
            InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type) =>
            throw new NotSupportedException("Read the rules from ReadAcl's result.");

        public override AuditRule AuditRuleFactory(
            System.Security.Principal.IdentityReference identityReference, int accessMask, bool isInherited,
            InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags flags) =>
            throw new NotSupportedException("Read the rules from ReadAcl's result.");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(
        string fileName, uint desiredAccess, FileShare shareMode, IntPtr securityAttributes, FileMode creationDisposition,
        uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string pathName, ref SecurityAttributes securityAttributes);

    [DllImport("ntdll.dll")]
    private static extern int NtOpenFile(
        out IntPtr fileHandle, uint desiredAccess, ref ObjectAttributes objectAttributes, out IoStatusBlock ioStatusBlock,
        uint shareAccess, uint openOptions);

    [DllImport("ntdll.dll")]
    private static extern int RtlNtStatusToDosError(int status);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file, int informationClass, out FileAttributeTagInfo information, uint size);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass, IntPtr information, uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetKernelObjectSecurity(SafeFileHandle handle, uint securityInformation, byte[] securityDescriptor);
}
