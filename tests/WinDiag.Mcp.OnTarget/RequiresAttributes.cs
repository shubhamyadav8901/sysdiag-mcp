using System.Security.Principal;
using WinDiag.Mcp.Diagnostics.External;

namespace WinDiag.Mcp.OnTarget;

/// <summary>
/// A fact that reports itself as skipped unless handle.exe is installed <em>and</em> the session is
/// elevated.
/// </summary>
/// <remarks>
/// <para>Both prerequisites are checked by one attribute because xUnit permits only a single
/// <see cref="FactAttribute"/> per method, and because handle.exe without elevation is not a partial
/// capability but a misleading one: it returns a shorter list rather than an error, so a test that ran
/// unelevated could fail for a reason that looks like a product bug.</para>
/// <para>Skipping loudly beats the alternatives -- failing makes an unelevated developer run look
/// broken, and returning early silently makes an unmet prerequisite look like a pass.</para>
/// </remarks>
public sealed class RequiresElevatedHandleExeFactAttribute : FactAttribute
{
    public RequiresElevatedHandleExeFactAttribute()
    {
        if (!new ToolLocator().TryResolve("handle.exe", out _))
        {
            Skip = "handle.exe is not installed on this machine.";
            return;
        }

        if (!IsElevated())
        {
            Skip = "Requires an elevated session; handle.exe loads a kernel driver.";
        }
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
