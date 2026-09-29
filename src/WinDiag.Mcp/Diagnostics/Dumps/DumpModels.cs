namespace WinDiag.Mcp.Diagnostics.Dumps;

/// <summary>How much of the target process to capture.</summary>
public enum DumpKind
{
    /// <summary>
    /// Stacks, thread and handle information, loaded modules — but not the process's memory.
    /// </summary>
    /// <remarks>
    /// Small and fast. Enough to answer "where is it stuck?" for a hang, which is the common case.
    /// </remarks>
    Mini,

    /// <summary>Everything, including full process memory.</summary>
    /// <remarks>
    /// The size of the process's working set and then some — routinely hundreds of megabytes and
    /// occasionally gigabytes. Needed when the question involves inspecting objects or buffers.
    /// </remarks>
    Full
}

/// <summary>A written crash dump.</summary>
/// <param name="UncPath">
/// The same file addressed through the machine's administrative share, so a debugger on another machine
/// can open it without copying. Null when the local path is not on a drive that maps to one.
/// </param>
/// <param name="TargetIsWow64">
/// True when the dumped process is 32-bit running on 64-bit Windows. It matters to whoever opens the
/// dump: written by a 64-bit process, it presents WOW64 frames rather than the real 32-bit stacks until
/// the debugger is switched over. Office add-ins and shell extensions frequently run in 32-bit hosts,
/// so this is the common case rather than an exotic one.
/// </param>
public sealed record DumpResult(
    string Path,
    string? UncPath,
    long SizeBytes,
    int ProcessId,
    string ProcessName,
    DumpKind Kind,
    bool Elevated,
    bool TargetIsWow64);

/// <summary>Writes crash dumps of live processes.</summary>
public interface IDumpWriter
{
    DumpResult Capture(int processId, DumpKind kind, CancellationToken cancellationToken);
}

/// <summary>Raised when a dump could not be written.</summary>
public sealed class DumpCaptureException : Exception, IDiagnosticException
{
    public DumpCaptureException(string message) : base(message)
    {
    }

    public DumpCaptureException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
