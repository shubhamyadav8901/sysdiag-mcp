namespace DiagRelay.Mcp.Tests;

/// <summary>A fact that runs only on Windows, and reports itself skipped elsewhere.</summary>
/// <remarks>
/// Skipped rather than returning early: an early return reads as Passed, and a platform check that
/// silently passes on the platform it does not cover is how coverage gets overstated.
/// </remarks>
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Windows only.";
        }
    }
}

/// <summary>A fact that runs only on Linux and macOS -- run it with tools/test-linux.sh.</summary>
public sealed class UnixFactAttribute : FactAttribute
{
    public UnixFactAttribute()
    {
        if (OperatingSystem.IsWindows())
        {
            Skip = "Unix only. Run tools/test-linux.sh.";
        }
    }
}
