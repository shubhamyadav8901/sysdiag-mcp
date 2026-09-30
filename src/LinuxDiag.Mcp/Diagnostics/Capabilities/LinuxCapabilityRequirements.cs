using LinuxDiag.Mcp.Diagnostics.Containers;

namespace LinuxDiag.Mcp.Diagnostics.Capabilities;

/// <summary>What each of this server's tools needs in order to answer completely.</summary>
/// <remarks>
/// Hand-maintained; GuardTests fails if it disagrees with the tools declared in this assembly and the
/// kit's. A RequiredExecutable is a program name, found by <see cref="PathExecutableResolver"/>.
/// </remarks>
public sealed class LinuxCapabilityRequirements : ICapabilityRequirements
{
    public IReadOnlyDictionary<string, CapabilityRequirement> Requirements => Table;

    private static readonly IReadOnlyDictionary<string, CapabilityRequirement> Table =
        new Dictionary<string, CapabilityRequirement>(StringComparer.Ordinal)
        {
            ["capabilities"] = new("this table, evaluated on this machine", null, null),
            ["put_file"] = new(
                "hash-verified file write over the server's own channel",
                null,
                "can only write where the current account already can"),
            ["get_file"] = new(
                "hash-verified sliced file read over the server's own channel",
                null,
                "can only read what the current account already can"),
            ["system_overview"] = new("/proc, /etc/os-release and statvfs per mount", null, null),
            ["run_command"] = new("/bin/sh -c, /bin/bash -c, or a direct exec", null, null),
            ["container_list"] = new(
                "Docker Engine API on /var/run/docker.sock; containerd task state under /run/containerd",
                null,
                "cannot reach the Docker socket or containerd's task state unless the account is root or in the docker group",
                AnyOfPaths: [DockerEngineClient.DefaultSocket, ContainerdTasks.StateRoot]),
            ["process_list"] = new(
                "/proc/<pid>/{stat,status,cmdline,cgroup}, joined with container_list's runtimes",
                null,
                "cannot read the executable path or namespaces of processes owned by other users, which are reported as null"),
            ["process_handles"] = new(
                "/proc/<pid>/fd, fdinfo and maps, scoped to one process",
                null,
                "cannot read the open files of processes owned by other users"),
            ["process_modules"] = new(
                "/proc/<pid>/maps",
                null,
                "cannot read the memory map of processes owned by other users"),
            ["update_self"] = new("staged-build swap through a systemd-run helper (setsid when not a service)", null, null, RequiresElevation: true),
        };
}
