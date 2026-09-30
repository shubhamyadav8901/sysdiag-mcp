namespace LinuxDiag.Mcp.Diagnostics.Network;

public sealed record PipeOwner(int ProcessId, string ProcessName);

/// <param name="Kind">UnixStream, UnixDatagram, UnixSeqPacket or Fifo.</param>
/// <param name="ConnectedCount">Connected sockets under this name -- the server side of each accepted connection; for a FIFO, the descriptors open on it.</param>
/// <param name="OtherMountNamespace">The name is a path in a holder's own mount namespace -- a container's -- not the host's.</param>
/// <param name="NetworkNamespace">A unix socket's network namespace; null for a FIFO, which has none.</param>
public sealed record NamedPipe(
    string Name, string Kind, bool Listening, int ConnectedCount, IReadOnlyList<PipeOwner> Owners,
    bool OtherMountNamespace, string? NetworkNamespace);

public sealed record NamedPipeList(IReadOnlyList<NamedPipe> Pipes, int TotalMatched, bool Truncated, IReadOnlyList<string> Limitations);

public interface IPipeInspector
{
    NamedPipeList List(string? nameFilter, CancellationToken cancellationToken);
}
