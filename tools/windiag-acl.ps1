<#
.SYNOPSIS
    Defines Protect-WinDiagDirectory, shared by the Windows deploy and bootstrap scripts, and
    New-WinDiagRestrictedFile, which bootstrap-target.ps1 uses for the token. Dot-source it.

.DESCRIPTION
    The directories windiag runs from are not safe by default. A folder made under C:\ -- the scripts'
    default C:\WinDiag and C:\WinDiagArtifacts -- inherits "Authenticated Users: Modify", and the SYSTEM
    service runs the Sysinternals binaries it finds beside itself and self-update.cmd from its artifact
    directory. So any local user could plant code it would run, or read its memory dumps.

    The installer and the service restrict these directories themselves. The scripts do it as well, and
    first, because they put things there before any installer runs: the build, and for the PsExec route
    the short-lived file that carries the token to the installer.

    Self-contained on purpose: bootstrap-winrm.ps1 sends this whole file to the target through
    Invoke-Command, where nothing else from this repo exists.
#>

function Test-WinDiagOwnDisk {
    <#
    .SYNOPSIS
        Whether Path is on one of this machine's own disks -- a drive letter that is fixed or removable --
        and not reached over the network.
    #>
    param([Parameter(Mandatory)] [string] $Path)

    # Who this machine's Administrators group holds says something only about ACLs this machine enforces.
    # bootstrap-target.ps1 and deploy-target.ps1 run Protect-WinDiagDirectory on the operator's workstation
    # against \\host\C$\...: the owners and ACEs read over SMB are the target's SIDs, and a direct member of
    # the workstation's group may be an ordinary user there, free to rename the folder and stage their own
    # build for PsExec to run as SYSTEM. A mapped drive is the same thing behind a letter. Anything not
    # recognisably local -- a UNC or \\?\ path, a drive this session cannot see -- counts as not, so the
    # doubt costs a refusal, never the target.
    try { $full = [System.IO.Path]::GetFullPath($Path) } catch { return $false }
    if ($full -notmatch '^[A-Za-z]:\\') { return $false }
    try { $type = (New-Object System.IO.DriveInfo $full.Substring(0, 1)).DriveType }
    catch { return $false }
    $type -eq [System.IO.DriveType]::Fixed -or $type -eq [System.IO.DriveType]::Removable
}

function Protect-WinDiagDirectory {
    param([Parameter(Mandatory)] [string] $Path)

    # A drive root -- C:\ locally, \\host\C$ over the admin share -- always lets users create folders,
    # and protecting it would lock every user out of the whole drive. The installer refuses it too.
    if ($Path -match '^([A-Za-z]:|\\\\[^\\]+\\[^\\]+)\\?$') {
        throw "$Path is the root of a drive. Give windiag a directory of its own, such as C:\WinDiag."
    }

    # The server's ProtectedAcl.ProtectDirectory restricts a directory that already exists, and takes over
    # what it holds, through handles opened without following links: every item judged and written through
    # one handle, and listed and opened relative to its parent's. A path is resolved again on every call,
    # so done by path -- Set-Acl, Get-ChildItem -- each step can be made to land somewhere else after the
    # check before it, by whoever can still write the directory, which is why it needs restricting. This
    # runs before anything from this repository is on the target -- bootstrap-winrm.ps1 sends this file
    # alone -- so it does not try: it creates a missing directory restricted from the start, and uses one
    # that exists only if it already is, refusing the rest with nothing changed. BootstrapAclScriptTests
    # runs it against what the server leaves.

    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root = [System.IO.Path]::GetPathRoot($full).TrimEnd('\')
    $components = @()
    for ($p = $full; $p -and $p.TrimEnd('\') -ne $root; $p = [System.IO.Path]::GetDirectoryName($p)) {
        $components = @($p) + $components
    }

    # Set-Acl and CreateDirectory follow a junction, so a C:\WinDiag that some user made a junction to
    # C:\Windows would have that restricted, or a directory made inside it -- and the junction stays theirs,
    # to point somewhere else once the check is done. A link above the directory is the same thing a level
    # up. Attributes read by path do not follow the last component, so each one is judged as itself. Not
    # asked whether it exists first: Directory.Exists follows a link, so a junction to nowhere -- which a
    # create through it would then bring into being -- would read as not there yet.
    function Assert-NoLinkOnTheWay {
        foreach ($component in $components) {
            try { $attributes = [System.IO.File]::GetAttributes($component) }
            catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] { return }
            if ($attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw (Get-LinkRefusal $component)
            }
        }
    }

    function Get-LinkRefusal([string] $Component) {
        "$Component is a link -- a junction, a symbolic link or a mounted folder" +
            $(if ($Component -ne $full) { ", and $full is reached through it" } else { '' }) +
            '. Whoever made it can point it somewhere else once it has been checked. Nothing was ' +
            'changed. Give windiag a directory of its own that no link leads to.'
    }

    # A directory's attributes and security, read through one handle opened on it and not on whatever it
    # links to. Get-Acl reads by path and follows a link: a junction its maker flips between a folder of
    # theirs and one of the system's would read as owned by TrustedInstaller between two checks that it is
    # no link. Through one handle, what is judged a link or not is what the owner and ACEs are read from.
    if (-not ('WinDiagAcl.Handle' -as [type])) {
        Add-Type -Namespace WinDiagAcl -Name Handle -MemberDefinition @'
[StructLayout(LayoutKind.Sequential)]
public struct TagInfo { public uint FileAttributes; public uint ReparseTag; }

[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(
    string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

[DllImport("kernel32.dll", SetLastError = true)]
private static extern bool GetFileInformationByHandleEx(
    Microsoft.Win32.SafeHandles.SafeFileHandle file, int infoClass, out TagInfo info, uint size);

[DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
private static extern int NetLocalGroupGetMembers(
    string server, string group, int level, out IntPtr buffer, int max, out int read, out int total, IntPtr resume);

[DllImport("netapi32.dll")]
private static extern int NetApiBufferFree(IntPtr buffer);

[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
private static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr text);

[DllImport("kernel32.dll")]
private static extern IntPtr LocalFree(IntPtr memory);

// The SIDs of the local group's direct members, as S-1-... strings; empty if they cannot be read.
public static string[] Members(string group)
{
    IntPtr buffer;
    int read, total;
    if (NetLocalGroupGetMembers(null, group, 0, out buffer, -1, out read, out total, IntPtr.Zero) != 0)
    {
        if (buffer != IntPtr.Zero) { NetApiBufferFree(buffer); }
        return new string[0];
    }
    try
    {
        var sids = new System.Collections.Generic.List<string>();
        for (int i = 0; i < read; i++)
        {
            IntPtr text;
            // LOCALGROUP_MEMBERS_INFO_0: one PSID each.
            if (!ConvertSidToStringSidW(Marshal.ReadIntPtr(buffer, i * IntPtr.Size), out text)) { continue; }
            try { sids.Add(Marshal.PtrToStringUni(text)); } finally { LocalFree(text); }
        }
        return sids.ToArray();
    }
    finally { NetApiBufferFree(buffer); }
}

[DllImport("advapi32.dll", SetLastError = true)]
private static extern bool GetKernelObjectSecurity(
    Microsoft.Win32.SafeHandles.SafeFileHandle handle, uint information, byte[] descriptor, uint length, out uint needed);

// 0 when read; otherwise the Win32 error: 2 or 3 when nothing is there, 5 when this account may not read it.
public static int Read(string path, out uint attributes, out byte[] descriptor)
{
    attributes = 0;
    descriptor = null;
    // READ_CONTROL | FILE_READ_ATTRIBUTES, any sharing, OPEN_EXISTING, BACKUP_SEMANTICS | OPEN_REPARSE_POINT.
    using (var handle = CreateFileW(path, 0x00020080, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero))
    {
        if (handle.IsInvalid) { return Marshal.GetLastWin32Error(); }
        TagInfo info;
        if (!GetFileInformationByHandleEx(handle, 9, out info, 8)) { return Marshal.GetLastWin32Error(); }
        attributes = info.FileAttributes;
        uint needed;
        GetKernelObjectSecurity(handle, 5, null, 0, out needed);   // OWNER | DACL; asks only for the size
        if (needed == 0) { return Marshal.GetLastWin32Error(); }
        descriptor = new byte[needed];
        if (!GetKernelObjectSecurity(handle, 5, descriptor, needed, out needed)) { return Marshal.GetLastWin32Error(); }
        return 0;
    }
}
'@
    }

    # SYSTEM, Administrators and TrustedInstaller -- the OS's own servicing account, which owns C:\ and
    # System32 and can replace the OS already. The same accounts the server trusts, less the service's own:
    # the scripts install as LocalSystem, and a directory another account can write is not one to stage a
    # binary into that PsExec then runs as SYSTEM.
    $trusted = 'S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3425522526-1101993487-2163447651-1013034063'

    # For the directories above $full, which these scripts never change, the group's direct members count as
    # well -- the server's ProtectedAcl.TrustedAbove. A D:\Ops locked to administrators by hand but made by
    # the built-in Administrator is owned by that account, not the group; refused, nothing short of changing
    # its owner would let it be used. Looked up by name, which is localised, from the group's SID. Members
    # reached only through a domain group are not counted: expanding one needs a domain controller.
    # Only on this machine's own disks: see Test-WinDiagOwnDisk. Over the admin share the target's group is
    # not asked either -- NetLocalGroupGetMembers against it would answer, but a second account database to
    # read and fall back from is more to get wrong than the refusal costs, which names the same owner fix.
    $ownDisk = Test-WinDiagOwnDisk $full
    $trustedAbove = $trusted
    if ($ownDisk) {
        try {
            $groupName = (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate(
                [System.Security.Principal.NTAccount]).Value.Split('\')[-1]
            $trustedAbove = @($trusted) + @([WinDiagAcl.Handle]::Members($groupName))
        }
        catch { }
    }
    $directoryWriteRights = 0x500D0046   # GENERIC_ALL | GENERIC_WRITE | write, append, delete child, delete, WRITE_DAC, WRITE_OWNER
    $renameRights = 0x100D0000           # GENERIC_ALL | DELETE | WRITE_DAC | WRITE_OWNER
    $removeChildRights = 0x100C0040      # GENERIC_ALL | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER

    # Who other than $trusted owns the descriptor's object, or holds any of $Rights on it through an allow
    # ACE that applies to it -- the server's ProtectedAcl.Exposures, in the same words.
    function Get-Exposure($Descriptor, [int] $Rights, [string] $Verb, [string[]] $Trust = $trusted) {
        $found = @()
        if ($Descriptor.Owner -and $Trust -notcontains $Descriptor.Owner.Value) {
            $found += "$(Get-AccountName $Descriptor.Owner) owns it, so can change who has access"
        }
        if ($null -eq $Descriptor.DiscretionaryAcl) {
            # No DACL at all: everyone may do anything. Not the same as an empty one, which admits nobody.
            $found += "it has no access list, so everyone can $Verb it"
            return $found
        }
        foreach ($ace in $Descriptor.DiscretionaryAcl) {
            if ($ace -isnot [System.Security.AccessControl.CommonAce] -or
                $ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed -or
                ($ace.AceFlags -band [System.Security.AccessControl.AceFlags]::InheritOnly) -or
                $ace.SecurityIdentifier.Value -eq 'S-1-3-0' -or       # CREATOR OWNER: only ever about a future child
                $Trust -contains $ace.SecurityIdentifier.Value) { continue }
            if ($ace.AccessMask -band $Rights) { $found += "$(Get-AccountName $ace.SecurityIdentifier) can $Verb it" }
        }
        $found | Select-Object -Unique
    }

    function Get-AccountName($Sid) {
        try { $Sid.Translate([System.Security.Principal.NTAccount]).Value } catch { $Sid.Value }
    }

    # Every directory from the drive root down to $full that exists, each through its own handle: none a
    # link; none above $full that anyone else could rename and replace with their own, everything below then
    # theirs; and $full itself writable, and owned, by nobody else. Returns what is wrong, empty when nothing.
    function Get-Problem {
        $problems = @()
        $parent = $null
        foreach ($component in @("$root\") + $components) {
            $attributes = [uint32] 0
            $bytes = $null
            $code = [WinDiagAcl.Handle]::Read($component, [ref] $attributes, [ref] $bytes)
            if ($code -eq 2 -or $code -eq 3) { break }   # not there yet, and so nothing below it is either
            if ($code -ne 0) {
                $problems += "$component cannot be read ($((New-Object System.ComponentModel.Win32Exception $code).Message)), so who can change it is unknown"
                break
            }
            if ($attributes -band [uint32][System.IO.FileAttributes]::ReparsePoint) { throw (Get-LinkRefusal $component) }
            if (-not ($attributes -band [uint32][System.IO.FileAttributes]::Directory)) { throw "$component is a file, not a directory. Nothing was changed." }

            $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $bytes, 0
            if ($component -ne "$root\") {
                $problems += @(Get-Exposure $parent $removeChildRights 'remove what is in' $trustedAbove) | ForEach-Object { "${parentPath}, which holds ${component}: $_" }
                if ($component -eq $full) {
                    $problems += @(Get-Exposure $descriptor $directoryWriteRights 'write to') | ForEach-Object { "${component}: $_" }
                }
                else {
                    $problems += @(Get-Exposure $descriptor $renameRights 'rename or remove' $trustedAbove) | ForEach-Object { "${component}, on the way to it: $_" }
                }
            }
            $parent = $descriptor
            $parentPath = $component
        }
        @($problems | Where-Object { $_ })
    }

    function Assert-Usable {
        $problems = @(Get-Problem)
        if ($problems.Count -gt 0) {
            throw ("$full cannot be used as it is: " + (($problems | Select-Object -First 5) -join '; ') +
                $(if ($problems.Count -gt 5) { "; and $($problems.Count - 5) more" } else { '' }) +
                '. Nothing was changed: these scripts change nothing in a directory that already exists, ' +
                'because doing that safely while someone else can still write it needs what only the ' +
                'installer and the service have. If windiag runs from it, let update_self bring the target ' +
                'to this release, whose server restricts it on its next start; otherwise rename it aside ' +
                '(Rename-Item) or pick another path, and run this again. A directory above it that others ' +
                'can rename must be restricted to administrators first; ' +
                $(if ($ownDisk) { 'one an account outside the local Administrators group owns' }
                  else { 'one any single account owns -- judged from this machine, over the network, whose own ' +
                         "Administrators group says nothing about the target's, even an administrator of the " +
                         'target counts as anyone else --' }) +
                ' must be handed to the group (icacls <dir> /setowner *S-1-5-32-544).')
        }
    }

    Assert-NoLinkOnTheWay

    # Judged before anything is created, so a refusal leaves nothing behind.
    Assert-Usable

    $administrators = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'

    # Protected (nothing inherited) rather than the one bad ACE removed: the next inheritance pass from
    # C:\ would put it straight back. Owned by Administrators because C:\ lets any user create a folder,
    # so this one may have been made by somebody waiting for an administrator to fill it -- and an
    # owner can restore any ACE removed here.
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administrators)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {   # SYSTEM, Administrators
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule (
            (New-Object System.Security.Principal.SecurityIdentifier $sid),
            'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }

    if (-not [System.IO.Directory]::Exists($Path)) {
        # Created with the ACL already on it, not given it afterwards: in between it would inherit
        # "Authenticated Users: Modify" from C:\, and a handle a user opened then keeps that access
        # whatever the ACL later says. Every missing directory above it is made the same way. Windows
        # PowerShell and PowerShell 7 spell this differently.
        if ($PSVersionTable.PSEdition -eq 'Core') {
            Add-Type -AssemblyName System.IO.FileSystem.AccessControl
            [void][System.IO.FileSystemAclExtensions]::CreateDirectory($acl, $Path)
        }
        else {
            [void][System.IO.Directory]::CreateDirectory($Path, $acl)
        }
    }

    # Judged again, whether this made it or not. CreateDirectory returns quietly when the directory is
    # there already, so one a user made in the moment since the check -- theirs, with their ACL, and
    # perhaps a file waiting at a name staging will write -- would otherwise pass as the one made here.
    Assert-NoLinkOnTheWay
    Assert-Usable
}

function New-WinDiagRestrictedFile {
    <#
    .SYNOPSIS
        Creates a file that only SYSTEM and Administrators can open, and writes Content into it.
    #>
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Content
    )

    # For the token on its way to the installer, and the .cmd that SYSTEM runs to feed it in. The ACL is
    # part of the create, not set after it, so no handle can be opened on the file before it is restricted
    # -- and an open handle keeps the access it was opened with whatever the ACL later says. CreateNew, so
    # a file or link already at this name fails the run instead of being written into: one a user left
    # there would be theirs, and so would the token. Callers name the file afresh for each run, so nobody
    # can have been waiting at the name.
    $security = New-Object System.Security.AccessControl.FileSecurity
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner((New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {   # SYSTEM, Administrators
        $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule (
            (New-Object System.Security.Principal.SecurityIdentifier $sid), 'FullControl', 'Allow')))
    }

    $rights = [System.Security.AccessControl.FileSystemRights]::Write
    if ($PSVersionTable.PSEdition -eq 'Core') {
        Add-Type -AssemblyName System.IO.FileSystem.AccessControl
        $stream = [System.IO.FileSystemAclExtensions]::Create([System.IO.FileInfo] $Path, [System.IO.FileMode]::CreateNew,
            $rights, [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::None, $security)
    }
    else {
        $stream = New-Object System.IO.FileStream ($Path, [System.IO.FileMode]::CreateNew, $rights,
            [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::None, $security)
    }

    try {
        $bytes = (New-Object System.Text.UTF8Encoding $false).GetBytes($Content)
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally {
        $stream.Dispose()
    }
}
