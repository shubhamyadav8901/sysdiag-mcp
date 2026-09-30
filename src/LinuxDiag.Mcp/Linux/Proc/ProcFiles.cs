using System.Globalization;

using LinuxDiag.Mcp.Linux.Native;

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
    public const string KernelRelease = "/proc/sys/kernel/osrelease";
    public const string KernelStat = "/proc/stat";
    public const string ProcRoot = "/proc";

    public static string Read(string path) => File.ReadAllText(path);

    /// <summary>The PIDs alive when /proc was listed. Any of them may be gone by the time it is read.</summary>
    public static IEnumerable<int> ProcessIds()
    {
        foreach (var directory in Directory.EnumerateDirectories(ProcRoot))
        {
            if (int.TryParse(Path.GetFileName(directory), NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
            {
                yield return pid;
            }
        }
    }

    public static string Of(int pid, string relative) => $"/proc/{pid}/{relative}";

    public static bool IsAlive(int pid) => Directory.Exists($"/proc/{pid}");

    /// <summary>A per-process file's text, or null when the process has exited.</summary>
    /// <remarks>
    /// "Exited" is decided by looking again, not by the exception: .NET reports ESRCH as a bare
    /// IOException and ENOENT as either of two types, so matching on type alone would also swallow a
    /// real read error from a live process. Permission denied is not an IOException and always propagates,
    /// so a caller can count it.
    /// </remarks>
    public static string? ReadProcess(int pid, string relative)
    {
        try
        {
            return File.ReadAllText(Of(pid, relative));
        }
        catch (IOException) when (!IsAlive(pid))
        {
            return null;
        }
    }

    /// <summary>A per-process link's raw target (<c>exe</c>, <c>ns/net</c>, <c>fd/3</c>), or null when the process has exited.</summary>
    public static string? ReadProcessLink(int pid, string relative)
    {
        try
        {
            return Link(Of(pid, relative));
        }
        catch (IOException) when (!IsAlive(pid))
        {
            return null;
        }
    }

    public const string Passwd = "/etc/passwd";

    /// <summary>One process's open descriptors and their raw link targets, or null when it has exited.</summary>
    /// <remarks>Permission denied propagates: another user's fd directory needs root, and a caller counts that.</remarks>
    public static IReadOnlyList<(int Descriptor, string Target)>? Descriptors(int pid)
    {
        try
        {
            var descriptors = new List<(int, string)>();
            foreach (var entry in Directory.EnumerateFileSystemEntries(Of(pid, "fd")))
            {
                if (!int.TryParse(Path.GetFileName(entry), NumberStyles.None, CultureInfo.InvariantCulture, out var fd))
                {
                    continue;
                }

                string? target;
                try
                {
                    target = Link(entry);
                }
                catch (IOException)
                {
                    // Closed between the listing and the readlink: it is no longer open, so it is not held.
                    continue;
                }

                if (target is not null)
                {
                    descriptors.Add((fd, target));
                }
            }

            return descriptors;
        }
        catch (IOException) when (!IsAlive(pid))
        {
            return null;
        }
    }

    /// <summary>A link's target through readlink(2) itself, so permission denied is not mistaken for "no link".</summary>
    private static string? Link(string path) => LibC.Supported ? LibC.ReadLink(path) : new FileInfo(path).LinkTarget;
}
