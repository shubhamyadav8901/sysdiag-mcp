namespace MacDiag.Mcp.Diagnostics.Handles;

/// <remarks>
/// No lock kinds: Darwin's lsof does not report lock state. Executing, Mapped, WorkingDirectory and RootDirectory pin
/// a file with no open descriptor -- a running binary is what "text file busy" means.
/// </remarks>
public enum LockHolderKind
{
    Open,
    Executing,
    Mapped,
    WorkingDirectory,
    RootDirectory,
    Other,
}

public sealed record LockHolder(int ProcessId, string ProcessName, LockHolderKind Kind, string? Access);

/// <param name="Exhaustive">Every process could be read (the server is root). Says nothing about locks.</param>
public sealed record LockQuery(
    string Path, bool PathExists, IReadOnlyList<LockHolder> Holders, bool Exhaustive, IReadOnlyList<string> Limitations,
    int TotalMatched, bool Truncated);

public interface ILockInspector
{
    Task<LockQuery> QueryAsync(string fullPath, CancellationToken cancellationToken);
}
