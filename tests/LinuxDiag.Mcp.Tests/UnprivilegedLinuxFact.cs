namespace LinuxDiag.Mcp.Tests;

/// <summary>A Linux fact that needs an account without root, which can read and look up anything.</summary>
/// <remarks>
/// Skipped rather than returning early under root: an early return reads as Passed. tools/test-linux.sh runs
/// as the WSL user, so these run there.
/// </remarks>
public sealed class UnprivilegedLinuxFactAttribute : FactAttribute
{
    public UnprivilegedLinuxFactAttribute()
    {
        if (!OperatingSystem.IsLinux())
        {
            Skip = "Linux only. Run tools/test-linux.sh.";
        }
        else if (Environment.IsPrivilegedProcess)
        {
            Skip = "Needs an unprivileged account: root can read every process.";
        }
    }
}

/// <summary>As <see cref="UnprivilegedLinuxFactAttribute"/>, on macOS as well: for a permission only root ignores.</summary>
public sealed class UnprivilegedUnixFactAttribute : FactAttribute
{
    public UnprivilegedUnixFactAttribute()
    {
        if (OperatingSystem.IsWindows())
        {
            Skip = "Unix only. Run tools/test-linux.sh.";
        }
        else if (Environment.IsPrivilegedProcess)
        {
            Skip = "Needs an unprivileged account: root lists any directory.";
        }
    }
}
