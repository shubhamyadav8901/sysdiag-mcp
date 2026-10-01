using System.Globalization;
using MacDiag.Mcp.Mac;

namespace MacDiag.Mcp.Hosting;

/// <summary>Whether this process was started by its own launchd job, rather than by hand.</summary>
/// <remarks>
/// Both halves. launchd sets XPC_SERVICE_NAME to the job's label, but a shell opened from a launchd-started session
/// can inherit it; only a daemon launchd started directly has launchd (PID 1) as its parent. Restarting through
/// launchctl from a by-hand run would restart the installed daemon instead of bringing this process back.
/// </remarks>
public static class LaunchdJob
{
    public static bool Matches(string? label, string? xpcServiceName, int parentProcessId) =>
        !string.IsNullOrWhiteSpace(label) && string.Equals(label, xpcServiceName, StringComparison.Ordinal) && parentProcessId == 1;

    /// <summary>The live check, asking ps for the parent: macOS gives .NET no API for it.</summary>
    public static bool IsOurs(string? label)
    {
        if (string.IsNullOrWhiteSpace(label) || Environment.GetEnvironmentVariable("XPC_SERVICE_NAME") != label)
        {
            return false;
        }

        try
        {
            var ps = new MacSystemCommand().RunAsync(
                "ps", ["-o", "ppid=", "-p", Environment.ProcessId.ToString(CultureInfo.InvariantCulture)], TimeSpan.FromSeconds(10), CancellationToken.None)
                .GetAwaiter().GetResult();
            return int.TryParse(ps.StandardOutput.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var parent) &&
                   Matches(label, label, parent);
        }
        catch (ExternalCommandException)
        {
            return false;
        }
    }
}
