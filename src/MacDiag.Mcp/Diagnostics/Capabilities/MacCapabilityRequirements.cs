namespace MacDiag.Mcp.Diagnostics.Capabilities;

/// <summary>What each of this server's tools needs in order to answer completely.</summary>
/// <remarks>
/// Hand-maintained; GuardTests fails if it disagrees with the tools declared in this assembly and the kit's.
/// A RequiredExecutable is found only in the runner's own directories (SystemExecutableResolver).
/// </remarks>
public sealed class MacCapabilityRequirements : ICapabilityRequirements
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
            ["system_overview"] = new("sw_vers, sysctl, vm_stat, mount, and each volume's size", "sw_vers", null),
            ["run_command"] = new("/bin/zsh -c, /bin/sh -c, /bin/bash -c, or a direct exec", null, null),
            ["process_list"] = new("ps -axww (pid, ppid, uid, rss, stat, lstart, args) joined with ps -axww -o pid,comm", "ps", null),
            ["process_handles"] = new("lsof -p, scoped to one process", "lsof", "cannot list the open files of processes owned by other users"),
            ["process_modules"] = new("lsof -p (txt entries); system libraries are in the dyld shared cache", "lsof", "cannot list the mapped files of processes owned by other users"),
            ["path_handle_search"] = new("a full lsof listing (-b) matched under every spelling of each name, plus lsof -f -- <path> by device and inode", "lsof", "cannot search processes owned by other users; the result says it is partial"),
            ["who_locks_path"] = new("lsof -f -- <path> by device and inode; lock state is not visible on macOS", "lsof", "cannot see files held by processes owned by other users, so it never reports Exhaustive"),
            ["network_owners"] = new("lsof -i -Ts, joined by each socket's kernel address", "lsof", "cannot name the owners of sockets held by processes owned by other users"),
            ["named_pipes"] = new("unix sockets and FIFOs from a full lsof listing (-b)", "lsof", "cannot name the holders of sockets and FIFOs owned by other users"),
            ["service_config"] = new("launchctl print for runtime state (top-level keys only); the job's plist via plutil -convert xml1 -o - for configuration", "launchctl", null),
            ["service_control"] = new("launchctl bootstrap, kickstart and bootout in the system domain", "launchctl", null, RequiresElevation: true),
            ["process_control"] = new("kill(1) after a ps name and start-time check, checked again just before the signal", "kill", "can only signal processes owned by the current user"),
            ["event_log_tail"] = new("log show --style ndjson over backward time windows", "log", null),
            ["container_list"] = new("Docker Engine API on /var/run/docker.sock and each user's Docker Desktop, Colima, OrbStack or Rancher Desktop socket, each checked for type, owner and the directories above it", null, "cannot reach another user's container engine unless the server runs as root"),
            ["file_signatures"] = new("SHA-256 via shasum; codesign --verify --strict and -dvvv; spctl --assess -v for app bundles; pkgutil --file-info", "codesign", null),
            ["autostart_audit"] = new("launchd plists via plutil, crontabs, periodic scripts, loginwindow hooks and SecurityAgent plugins, each file and the directories above it statted; codesign when signatures are checked", MacDiag.Mcp.Mac.Launchd.Plutil.Program, "cannot read users' crontabs, root's login hooks or homes it has no access to without root"),
            ["update_self"] = new("staged-build swap through a detached helper and launchctl kickstart (a relaunch when not a daemon), rolled back if the new build does not come up", null, null, RequiresElevation: true),
        };
}
