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
        };
}
