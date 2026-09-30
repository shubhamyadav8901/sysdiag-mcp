namespace LinuxDiag.Mcp.Diagnostics.Handles;

/// <remarks>
/// Executing, Mapped, WorkingDirectory and RootDirectory pin a file with no open descriptor: a running binary
/// is what "text file busy" means.
/// </remarks>
public enum LockHolderKind
{
    Open,
    Flock,
    Posix,
    OpenFileDescription,
    Lease,
    Delegation,
    Executing,
    Mapped,
    WorkingDirectory,
    RootDirectory,
    Other,
}

/// <param name="Confirmed">
/// Seen through the holder's own open file. False when only /proc/locks names it: for a FLOCK or OFD lock
/// that is the process that created the lock, which may have exited or handed the file to a child.
/// </param>
/// <param name="StillRunning">False means the PID is no longer this process: never act on it.</param>
public sealed record LockHolder(
    int ProcessId, string ProcessName, LockHolderKind Kind, string? Access, bool Waiting, bool Confirmed,
    DateTimeOffset? StartedAt, bool StillRunning);

public sealed record LockQuery(
    string Path, bool PathExists, IReadOnlyList<LockHolder> Holders, bool Exhaustive, IReadOnlyList<string> Limitations);

public interface ILockInspector
{
    LockQuery Query(string fullPath, CancellationToken cancellationToken);
}
