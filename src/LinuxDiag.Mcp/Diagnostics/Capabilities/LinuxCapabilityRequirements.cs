using LinuxDiag.Mcp.Diagnostics.Containers;
using LinuxDiag.Mcp.Linux.Packages;

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
            ["path_handle_search"] = new(
                "/proc/<pid>/fd and maps across every process, and statx identity for a full path",
                null,
                "returns a partial list, silently omitting files held by processes owned by other users"),
            ["who_locks_path"] = new(
                "statx identity against every /proc/<pid>/fd, fdinfo lock lines and /proc/locks",
                null,
                "cannot see files held by processes owned by other users, so it never reports Exhaustive"),
            ["network_owners"] = new(
                "/proc/<pid>/net/{tcp,tcp6,udp,udp6} per network namespace; owners by socket inode across /proc/<pid>/fd",
                null,
                "cannot name the owners of sockets held by processes owned by other users"),
            ["named_pipes"] = new(
                "/proc/<pid>/net/unix per network namespace, and FIFOs among /proc/<pid>/fd",
                null,
                "cannot name the holders of sockets and FIFOs owned by other users"),
            ["process_control"] = new(
                "signals through a pidfd (pidfd_open, pidfd_send_signal); Linux 5.3 or later",
                null,
                "can only signal processes owned by the current user"),
            ["service_config"] = new("systemctl show", "systemctl", null),
            ["service_control"] = new("systemctl start/stop/restart", "systemctl", null, RequiresElevation: true),
            ["event_log_tail"] = new(
                "journalctl -o json",
                "journalctl",
                "sees only this account's own records unless it is root or in the systemd-journal or adm group"),
            ["file_signatures"] = new(
                "SHA-256, and ownership and checksums from the dpkg database",
                null,
                null,
                AnyOfPaths: [DpkgDatabase.DefaultRoot + "/info"]),
            ["autostart_audit"] = new(
                "systemctl list-unit-files and show, crontabs, rc.local, profile.d, ld.so.preload, and the dpkg database",
                "systemctl",
                "cannot read users' crontabs or unreadable home directories, so those entries are silently absent"),
            ["effective_access"] = new(
                "statx, POSIX ACLs and file capabilities from extended attributes, /proc/self/mountinfo, faccessat",
                null,
                "cannot evaluate a path behind a directory the server's own account cannot search"),
            ["update_self"] = new("staged-build swap through a systemd-run helper (setsid when not a service)", null, null, RequiresElevation: true),
        };
}
