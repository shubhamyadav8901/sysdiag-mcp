namespace LinuxDiag.Mcp.Linux.Proc;

/// <summary>The one place this server reads /proc, /sys and /etc system files.</summary>
/// <remarks>
/// Kept in one class so what the server reads off a live machine is findable in one place, and parsers
/// never do I/O -- which is what lets every parser be tested on any OS with captured text.
/// </remarks>
public static class ProcFiles
{
    public const string OsRelease = "/etc/os-release";
    public const string Meminfo = "/proc/meminfo";
    public const string Uptime = "/proc/uptime";
    public const string Mounts = "/proc/self/mounts";

    public static string Read(string path) => File.ReadAllText(path);
}
