namespace LinuxDiag.Mcp.Diagnostics.Handles;

/// <param name="HandleValue">The descriptor number, or "mmap" for a mapped file.</param>
/// <param name="User">The holder's user name, from /etc/passwd; windiag's field. UserId is the number behind it.</param>
/// <param name="Access">"read", "write" or "read-write": how the holder opened it.</param>
/// <param name="OtherMountNamespace">The name is a path in the holder's own mount namespace -- a container's -- not the host's.</param>
public sealed record HandleEntry(
    string ProcessName, int ProcessId, string Type, string? User, long? UserId, string HandleValue, string Name,
    string? Access, bool OtherMountNamespace);

public sealed record HandleSearch(
    string Query, IReadOnlyList<HandleEntry> Entries, bool Elevated, bool Truncated, int TotalMatched,
    int UnreadableProcesses, bool IncludedAllObjectTypes, bool ProcessScoped);

public interface IHandleInspector
{
    HandleSearch ForProcess(int processId, bool includeAllObjectTypes, CancellationToken cancellationToken);

    HandleSearch Search(string nameFragment, bool includeAllObjectTypes, CancellationToken cancellationToken);
}

public sealed class HandleQueryException : Exception, IDiagnosticException
{
    public HandleQueryException(string message)
        : base(message)
    {
    }

    public HandleQueryException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
