namespace LinuxDiag.Mcp.Linux.Parsers;

/// <summary>How /proc is mounted, where that changes what a process walk can see.</summary>
public static class ProcMount
{
    /// <summary>Whether /proc hides other users' processes from an unprivileged reader altogether.</summary>
    /// <remarks>
    /// hidepid=invisible (2) and ptraceable (4) remove other users' /proc directories: those processes are not
    /// unreadable, they are absent, so no count of unreadable processes ever mentions them. noaccess (1) leaves the
    /// directories visible and denies their contents, which the walk already counts.
    /// </remarks>
    public static bool HidesOtherUsers(IReadOnlyList<MountInfoEntry> mounts)
    {
        ArgumentNullException.ThrowIfNull(mounts);

        var proc = mounts.LastOrDefault(m => m.MountPoint == "/proc");
        return proc is not null && proc.Options.Any(o => o is "hidepid=2" or "hidepid=invisible" or "hidepid=4" or "hidepid=ptraceable");
    }
}
