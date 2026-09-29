using System.Runtime.Versioning;
using System.Security.Principal;
using Diag.Mcp.Server.Capabilities;

namespace WinDiag.Mcp.Diagnostics;

/// <inheritdoc />
[SupportedOSPlatform("windows")]
public sealed class WindowsPrivilegeProbe : IPrivilegeProbe
{
    private readonly Lazy<bool> _isElevated = new(static () =>
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    });

    public bool IsElevated => _isElevated.Value;
}
