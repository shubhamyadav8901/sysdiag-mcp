namespace WinDiag.Mcp.Diagnostics.Pipes;

/// <summary>One named pipe and how much of its instance budget is in use.</summary>
/// <param name="MaximumInstances">
/// -1 when the pipe was created with PIPE_UNLIMITED_INSTANCES, which is reported as unlimited rather
/// than as a nonsensical negative capacity.
/// </param>
public sealed record NamedPipe(string Name, int ActiveInstances, int MaximumInstances)
{
    /// <summary>True when the pipe has a fixed limit and every instance is in use.</summary>
    /// <remarks>
    /// This is the condition that makes a client hang or fail to connect while the server looks
    /// perfectly healthy, so it is computed here rather than left to the reader.
    /// </remarks>
    public bool Exhausted => MaximumInstances > 0 && ActiveInstances >= MaximumInstances;

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
