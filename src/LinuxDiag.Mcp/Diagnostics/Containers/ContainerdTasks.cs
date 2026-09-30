using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Diagnostics.Containers;

/// <summary>containerd's running tasks, from its v2 runtime state directory.</summary>
public static class ContainerdTasks
{
    public const string StateRoot = "/run/containerd/io.containerd.runtime.v2.task";

    /// <summary>Docker's own namespace: the Engine API describes those containers better, with names.</summary>
    private const string DockerNamespace = "moby";

    public static (IReadOnlyList<ContainerdTaskEntry> Tasks, string? Limitation) Read()
    {
        if (!Directory.Exists(StateRoot))
        {
            return ([], null);
        }

        var tasks = new List<ContainerdTaskEntry>();
        try
        {
            foreach (var nsDirectory in Directory.EnumerateDirectories(StateRoot))
            {
                var ns = Path.GetFileName(nsDirectory);
                if (ns == DockerNamespace)
                {
                    continue;
                }

                foreach (var taskDirectory in Directory.EnumerateDirectories(nsDirectory))
                {
                    // A task that stops mid-walk takes its directory with it; skip it, as /proc walks do.
                    try
                    {
                        var config = File.ReadAllText(Path.Combine(taskDirectory, "config.json"));
                        var initPid = Path.Combine(taskDirectory, "init.pid");
                        tasks.Add(ContainerdTask.Parse(
                            ns, Path.GetFileName(taskDirectory), config,
                            File.Exists(initPid) ? File.ReadAllText(initPid) : null));
                    }
                    catch (Exception ex) when (ex is IOException or FormatException)
                    {
                    }
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            return ([], $"containerd's task state in {StateRoot} is not readable by this account; run the server " +
                        "as root to see containerd and Kubernetes containers.");
        }

        return (tasks, null);
    }
}
