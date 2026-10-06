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

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }

    # Protected (nothing inherited) rather than the one bad ACE removed: the next inheritance pass from
    # C:\ would put it straight back. Owned by Administrators because C:\ lets any user create a folder,
    # so this one may have been made by somebody waiting for an administrator to fill it -- and an
    # owner can restore any ACE removed here.
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {   # SYSTEM, Administrators
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule (
            (New-Object System.Security.Principal.SecurityIdentifier $sid),
            'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }

    Set-Acl -LiteralPath $Path -AclObject $acl
}
