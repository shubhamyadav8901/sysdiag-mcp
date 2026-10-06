<#
.SYNOPSIS
    Defines Protect-WinDiagDirectory, shared by the Windows deploy and bootstrap scripts. Dot-source it.

.DESCRIPTION
    The directories windiag runs from are not safe by default. A folder made under C:\ -- the scripts'
    default C:\WinDiag and C:\WinDiagArtifacts -- inherits "Authenticated Users: Modify", and the SYSTEM
    service runs the Sysinternals binaries it finds beside itself and self-update.cmd from its artifact
    directory. So any local user could plant code it would run, or read its memory dumps.

    The installer and the service restrict these directories themselves. The scripts do it as well, and
    first, because they put things there before any installer runs: the build, and for the PsExec route
    the short-lived file that carries the token to the installer.

    Self-contained on purpose: bootstrap-winrm.ps1 sends the function body to the target through
    Invoke-Command, where nothing else from this repo exists.
#>

function Protect-WinDiagDirectory {
    param([Parameter(Mandatory)] [string] $Path)

    # A drive root -- C:\ locally, \\host\C$ over the admin share -- always lets users create folders,
    # and protecting it would lock every user out of the whole drive. The installer refuses it too.
    if ($Path -match '^([A-Za-z]:|\\\\[^\\]+\\[^\\]+)\\?$') {
        throw "$Path is the root of a drive. Give windiag a directory of its own, such as C:\WinDiag."
    }

    # The same rule as ProtectedAcl.ProtectDirectory in the server, written twice because this runs before
    # anything from this repository is on the target: bootstrap-winrm.ps1 sends this function alone.
    # BootstrapAclScriptTests runs both on the same planted directory and compares what they leave.

    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root = [System.IO.Path]::GetPathRoot($full).TrimEnd('\')
    $components = @()
    for ($p = $full; $p -and $p.TrimEnd('\') -ne $root; $p = [System.IO.Path]::GetDirectoryName($p)) {
        $components = @($p) + $components
    }

    # Set-Acl follows a junction, so a C:\WinDiag that some user made a junction to C:\Windows would have
    # that restricted and handed to Administrators instead -- and the junction stays theirs, to point
    # somewhere else once the check is done. A link above the directory is the same thing a level up.
    # Attributes read by path do not follow the last component, so each one is judged as itself.
    function Assert-NoLinkOnTheWay {
        foreach ($component in $components) {
            if (-not ([System.IO.Directory]::Exists($component) -or [System.IO.File]::Exists($component))) { return }
            if ([System.IO.File]::GetAttributes($component) -band [System.IO.FileAttributes]::ReparsePoint) {
                throw ("$component is a link -- a junction, a symbolic link or a mounted folder" +
                       $(if ($component -ne $full) { ", and $full is reached through it" } else { '' }) +
                       '. Whoever made it can point it somewhere else once it has been checked. Nothing was ' +
                       'changed. Give windiag a directory of its own that no link leads to.')
            }
        }
    }

    # A junction or symbolic link would carry the takeover below to wherever it points -- a user's profile,
    # or System32. A hard link would too, less visibly: it is the same file as one elsewhere, and a user can
    # give any file they can read a second name. Refused rather than skipped: a link nobody expected is
    # itself the warning, and windiag never makes either.
    function Assert-Ownable([System.IO.FileSystemInfo] $Item) {
        if ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw ("$($Item.FullName) is a link, which windiag never puts in its directories. " +
                   "Nothing beneath it was changed; remove it and run this again.")
        }
        if (-not $Item.PSIsContainer -and $Item.LinkType -eq 'HardLink') {
            throw ("$($Item.FullName) is a hard link: the same file as one elsewhere on the volume, so " +
                   'restricting it would restrict that one too. Windiag never makes one. Remove it and run this again.')
        }
    }

    # Before anything is changed, so a directory holding a link is refused untouched. Checked again item
    # by item during the takeover, since until the directory is restricted its contents can still change.
    function Assert-NothingLinked([string] $Directory) {
        foreach ($item in @(Get-ChildItem -LiteralPath $Directory -Force)) {
            Assert-Ownable $item
            if ($item.PSIsContainer) { Assert-NothingLinked $item.FullName }
        }
    }

    Assert-NoLinkOnTheWay

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

    $existed = [System.IO.Directory]::Exists($Path)
    if (-not $existed) {
        # Created with the ACL already on it, not given it afterwards: in between it would inherit
        # "Authenticated Users: Modify" from C:\, and a handle a user opened then keeps that access
        # whatever the ACL later says. Windows PowerShell and PowerShell 7 spell this differently.
        if ($PSVersionTable.PSEdition -eq 'Core') {
            Add-Type -AssemblyName System.IO.FileSystem.AccessControl
            [void][System.IO.FileSystemAclExtensions]::CreateDirectory($acl, $Path)
        }
        else {
            [void][System.IO.Directory]::CreateDirectory($Path, $acl)
        }
    }
    else {
        Assert-NothingLinked $Path
    }

    Set-Acl -LiteralPath $Path -AclObject $acl

    # Again, now that only administrators can rename it: had it been swapped for a junction between the
    # check above and Set-Acl, the takeover below must not follow it. The server's own copy closes that
    # gap entirely by holding the directory open; a script sent bare to a target cannot.
    Assert-NoLinkOnTheWay

    # What was already inside keeps its own owner and its explicit ACEs through the change above -- only
    # inherited ACEs are replaced -- and an owner can always grant itself write access again. A user who
    # made C:\WinDiag first could otherwise keep a file in it that the staging copy then overwrites in
    # place, keeping their ownership, and rewrite it after the hash check. So every item is handed to
    # Administrators, and every explicit ACE it had is replaced by SYSTEM and Administrators only. A
    # container is listed only after it is restricted, so nothing can be added to it between the listing
    # and the reset.
    function Reset-WinDiagContents([string] $Directory) {
        foreach ($item in @(Get-ChildItem -LiteralPath $Directory -Force)) {
            Assert-Ownable $item

            # Explicit SYSTEM and Administrators ACEs, and inheritance left on so a service account's ACE on
            # the directory still reaches the item. Never a security object with no rules added: a fresh one
            # holds .NET's null-DACL placeholder, which Set-Acl writes as "Everyone: Full Control" -- every
            # file here, the server binary included, would become writable by every user.
            if ($item.PSIsContainer) {
                $itemAcl = New-Object System.Security.AccessControl.DirectorySecurity
                $inherit = 'ContainerInherit, ObjectInherit'
            }
            else {
                $itemAcl = New-Object System.Security.AccessControl.FileSecurity
                $inherit = 'None'
            }
            $itemAcl.SetOwner($administrators)
            $itemAcl.SetAccessRuleProtection($false, $false)
            foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {   # SYSTEM, Administrators
                $itemAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule (
                    (New-Object System.Security.Principal.SecurityIdentifier $sid),
                    'FullControl', $inherit, 'None', 'Allow')))
            }
            Set-Acl -LiteralPath $item.FullName -AclObject $itemAcl

            if ($item.PSIsContainer) { Reset-WinDiagContents $item.FullName }
        }
    }

    if ($existed) {
        $held = @(Get-ChildItem -LiteralPath $Path -Force | ForEach-Object Name)
        Reset-WinDiagContents $Path
        if ($held.Count -gt 0) {
            Write-Warning ("$Path already existed and held: $(($held | Select-Object -First 5) -join ', ')" +
                $(if ($held.Count -gt 5) { ', ...' } else { '' }) + '. It is now owned by Administrators and ' +
                'writable only by SYSTEM and Administrators, but whatever it holds was put there before, and a ' +
                'handle opened on it before keeps its access until it is closed: staging replaces windiag''s ' +
                'own files; remove anything else, and restart the target if in doubt.')
        }
    }
}
