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

    $existed = Test-Path -LiteralPath $Path
    if (-not $existed) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
    elseif ((Get-Item -LiteralPath $Path -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        # Set-Acl follows a junction, so a C:\WinDiag that some user made a junction to C:\Windows would
        # have that restricted and handed to Administrators instead.
        throw "$Path is a link to somewhere else, not a directory of windiag's own. Remove it and run this again."
    }

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

    Set-Acl -LiteralPath $Path -AclObject $acl

    # What was already inside keeps its own owner and its explicit ACEs through the change above -- only
    # inherited ACEs are replaced -- and an owner can always grant itself write access again. A user who
    # made C:\WinDiag first could otherwise keep a file in it that the staging copy then overwrites in
    # place, keeping their ownership, and rewrite it after the hash check. So every item is handed to
    # Administrators and left with only what it inherits from here. A container is listed only after it
    # is restricted, so nothing can be added to it between the listing and the reset.
    function Reset-WinDiagContents([string] $Directory) {
        foreach ($item in @(Get-ChildItem -LiteralPath $Directory -Force)) {
            # A junction or symbolic link would carry the reset to wherever it points -- a user's profile,
            # or System32. Refused rather than skipped: a link nobody expected is itself the warning.
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw ("$($item.FullName) is a link, which windiag never puts in its directories. " +
                       "Nothing beneath it was changed; remove it and run this again.")
            }

            $itemAcl = if ($item.PSIsContainer) { New-Object System.Security.AccessControl.DirectorySecurity }
                       else { New-Object System.Security.AccessControl.FileSecurity }
            $itemAcl.SetOwner($administrators)
            $itemAcl.SetAccessRuleProtection($false, $false)   # no explicit ACEs; inherit from the parent
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
                'writable only by SYSTEM and Administrators, but whatever it holds was put there before: ' +
                "staging replaces windiag's own files; remove anything else.")
        }
    }
}
