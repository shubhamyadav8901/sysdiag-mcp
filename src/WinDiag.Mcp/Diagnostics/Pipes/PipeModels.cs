namespace WinDiag.Mcp.Diagnostics.Pipes;

/// <summary>One named pipe: how many server instances exist, and whether a client could connect.</summary>
/// <param name="InstancesCreated">
/// Server instances that exist -- one per <c>CreateNamedPipe</c> -- whether or not a client is connected
/// to any of them. It is <em>not</em> a count of instances in use: a pipe created once with a limit of
/// one, and waiting for its first client, reads 1 of 1.
/// </param>
/// <param name="MaximumInstances">
/// -1 when the pipe was created with PIPE_UNLIMITED_INSTANCES, which is reported as unlimited rather
/// than as a nonsensical negative capacity.
/// </param>
/// <param name="Listening">
/// For a pipe with <see cref="AllInstancesCreated"/>: whether one of its instances was waiting for a
/// client when probed. Null when the pipe was not probed -- it can still create another instance -- or
/// the probe could not tell.
/// </param>
public sealed record NamedPipe(string Name, int InstancesCreated, int MaximumInstances, bool? Listening = null)
{
    /// <summary>True when the server has created every instance its limit allows and cannot add one.</summary>
    /// <remarks>
    /// Neutral on purpose. This used to be "Exhausted", reported as "a client will block or fail" -- but
    /// the count includes instances still listening, so every single-instance pipe waiting for its first
    /// client was flagged, and the caller was sent after a server that would have accepted them.
    /// </remarks>
    public bool AllInstancesCreated => MaximumInstances > 0 && InstancesCreated >= MaximumInstances;

    /// <summary>
    /// True when every instance is created and none was listening: a client connecting now waits, or
    /// gets ERROR_PIPE_BUSY, until the server frees one.
    /// </summary>
    public bool Busy => AllInstancesCreated && Listening == false;

    public bool Unlimited => MaximumInstances < 0;
}

/// <summary>Result of enumerating named pipes.</summary>
public sealed record NamedPipeListResult(
    IReadOnlyList<NamedPipe> Pipes,
    int TotalMatched,
    bool Truncated);

/// <summary>Enumerates named pipes on the local machine.</summary>
public interface INamedPipeInspector
{
    NamedPipeListResult List(string? nameFilter, CancellationToken cancellationToken);
}
