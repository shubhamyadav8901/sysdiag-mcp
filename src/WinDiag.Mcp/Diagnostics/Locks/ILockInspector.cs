namespace WinDiag.Mcp.Diagnostics.Locks;

/// <summary>Finds processes holding a filesystem path open.</summary>
public interface ILockInspector
{
    /// <summary>Queries holders of <paramref name="path"/>.</summary>
    /// <exception cref="LockQueryException">The query could not be performed.</exception>
    LockQueryResult WhoLocks(string path, CancellationToken cancellationToken);
}

/// <summary>Raised when a lock query fails outright, as opposed to finding nothing.</summary>
/// <remarks>
/// The distinction matters to the caller: "I could not look" and "I looked and found nothing" lead to
/// very different next steps, and collapsing them is how an investigation stops early on a false negative.
/// </remarks>
public sealed class LockQueryException : Exception
{
    public LockQueryException(string message) : base(message)
    {
    }

    public LockQueryException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
