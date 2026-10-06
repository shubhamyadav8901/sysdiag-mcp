using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace WinDiag.Mcp.Hosting;

/// <summary>
/// Files and directories opened as themselves -- never through a link -- and their ACLs read and written
/// through that same handle.
/// </summary>
/// <remarks>
/// <para>Everything .NET offers for a directory's ACL works by path, and a path is resolved again on every
/// call. Judging an item by one call and writing its ACL with another leaves a moment in which whoever can
/// still write it -- that is why it is being taken over -- turns an empty directory into a mount point, and
/// the write, and everything after it, lands on wherever that points. Through one handle opened without
/// following a link, the object judged is the object written.</para>
/// <para><see cref="SetSecurityInfo"/> on a handle applies inheritance as it does by path: an unprotected
/// DACL takes its parent's inheritable ACEs, and inheritable ACEs are carried to existing children.</para>
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
    private const uint BackupSemantics = 0x02000000;
    private const uint OpenReparsePoint = 0x00200000;
    private const int FileAttributeTagInfoClass = 9;

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

    /// <summary>Opens <paramref name="path"/> itself, never what it links to; null when nothing is there.</summary>
    /// <exception cref="UnauthorizedAccessException">This account may not open it with <paramref name="access"/>.</exception>
    public static SafeFileHandle? Open(string path, uint access, FileShare share)
    {
        var handle = CreateFile(path, access, share, IntPtr.Zero, FileMode.Open, BackupSemantics | OpenReparsePoint, IntPtr.Zero);
        if (!handle.IsInvalid)
        {
            return handle;
        }

        var error = Marshal.GetLastPInvokeError();
        handle.Dispose();
        return error is ErrorFileNotFound or ErrorPathNotFound ? null : throw Failure(path, error);
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

    /// <summary>Writes the owner, if <paramref name="acl"/> names one, and the DACL, to what <paramref name="handle"/> has open.</summary>
    /// <remarks>Needs <see cref="WriteDac"/>, and <see cref="WriteOwner"/> when an owner is written.</remarks>
    public static void WriteAcl(SafeFileHandle handle, FileSystemSecurity acl, bool isDirectory) =>
        new HandleSecurity(isDirectory, acl).Write(handle);

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

    /// <summary>A file object's security read or written through a handle, which DirectorySecurity cannot do.</summary>
    /// <remarks>
    /// The protected members of <see cref="NativeObjectSecurity"/> are the runtime's own handle-based read
    /// and write -- the ones <c>FileStream.SetAccessControl</c> uses -- so nothing here re-implements how
    /// a security descriptor is marshalled.
    /// </remarks>
    private sealed class HandleSecurity : NativeObjectSecurity
    {
        public HandleSecurity(bool isDirectory, SafeHandle handle)
            : base(isDirectory, ResourceType.FileObject, handle, AccessControlSections.Access | AccessControlSections.Owner)
        {
        }

        public HandleSecurity(bool isDirectory, FileSystemSecurity from)
            : base(isDirectory, ResourceType.FileObject) =>
            SetSecurityDescriptorBinaryForm(from.GetSecurityDescriptorBinaryForm(), AccessControlSections.All);

        // Owner only when the descriptor has one: NativeObjectSecurity writes a section only if it is set.
        public void Write(SafeHandle handle) => Persist(handle, AccessControlSections.Access | AccessControlSections.Owner);

        public override Type AccessRightType => typeof(FileSystemRights);

        public override Type AccessRuleType => typeof(FileSystemAccessRule);

        public override Type AuditRuleType => typeof(FileSystemAuditRule);

        // Never asked for: rules are read from the DirectorySecurity or FileSecurity ReadAcl copies this into.
        public override AccessRule AccessRuleFactory(
            IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags,
            PropagationFlags propagationFlags, AccessControlType type) =>
            throw new NotSupportedException("Read the rules from ReadAcl's result.");

        public override AuditRule AuditRuleFactory(
            IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags,
            PropagationFlags propagationFlags, AuditFlags flags) =>
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

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(
        string fileName, uint desiredAccess, FileShare shareMode, IntPtr securityAttributes, FileMode creationDisposition,
        uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file, int informationClass, out FileAttributeTagInfo information, uint size);
}
