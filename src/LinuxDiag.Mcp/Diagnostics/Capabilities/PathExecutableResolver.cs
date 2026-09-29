namespace LinuxDiag.Mcp.Diagnostics.Capabilities;

/// <summary>Finds a helper program the way a shell would, plus the sbin directories.</summary>
/// <remarks>
/// The standard directories are searched after PATH because a systemd service's PATH is its own and can
/// be shorter than a login shell's: a tool present at /usr/sbin/getfacl would otherwise be reported
/// missing to a caller who can see it right there.
/// </remarks>
public sealed class PathExecutableResolver : IExecutableResolver
{
    private static readonly string[] StandardDirectories =
        ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"];

    private const UnixFileMode AnyExecute =
        UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;

    public ExecutableResolution Resolve(string baseName)
    {
        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        return Find(baseName, path.Split(':', StringSplitOptions.RemoveEmptyEntries).Concat(StandardDirectories));
    }

    internal static ExecutableResolution Find(string baseName, IEnumerable<string> directories)
    {
        foreach (var directory in directories.Distinct(StringComparer.Ordinal))
        {
            var candidate = Path.Combine(directory, baseName);
            if (File.Exists(candidate) && (File.GetUnixFileMode(candidate) & AnyExecute) != 0)
            {
                return new ExecutableResolution(candidate, null);
            }
        }

        return new ExecutableResolution(
            null,
            $"'{baseName}' is not installed on this machine: it is not on PATH or in the standard bin and " +
            "sbin directories.");
    }
}
