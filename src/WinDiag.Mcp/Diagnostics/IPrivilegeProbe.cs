using System.Runtime.Versioning;
using System.Security.Principal;

namespace WinDiag.Mcp.Diagnostics;

/// <summary>Reports the privilege level the server itself is running with.</summary>
/// <remarks>
/// Several capabilities (exhaustive handle search, ETW kernel tracing, dumping another user's process)
/// silently degrade rather than fail cleanly when unelevated. Tools consult this so they can say
/// "this result may be incomplete because I am not elevated" instead of reporting a partial answer as
/// if it were the whole truth.
/// </remarks>
public interface IPrivilegeProbe
{
    /// <summary>True when the process holds the local Administrators role.</summary>
    bool IsElevated { get; }
}

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
