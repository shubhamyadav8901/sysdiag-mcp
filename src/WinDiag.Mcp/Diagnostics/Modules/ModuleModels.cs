namespace WinDiag.Mcp.Diagnostics.Modules;

/// <summary>One DLL or executable image loaded into a process.</summary>
/// <param name="SignatureVerdict">Null unless signature verification was requested.</param>
public sealed record LoadedModule(
    string Name,
    string Path,
    string BaseAddress,
    long SizeBytes,
    string? FileVersion,
    string? CompanyName,
    string? SignatureVerdict,
    string? Signer);

/// <summary>Result of listing a process's loaded modules.</summary>
/// <param name="Limitation">
/// Set when the list is known to be incomplete or unreadable — most often a bitness mismatch between
/// this server and the target. Stated explicitly because a short module list looks exactly like a
/// process that has loaded very little.
/// </param>
public sealed record ModuleListResult(
    int ProcessId,
    string ProcessName,
    IReadOnlyList<LoadedModule> Modules,
    int TotalMatched,
    bool Truncated,
    int UnsignedCount,
    string? Limitation);

/// <summary>Lists the images loaded into a running process.</summary>
public interface IModuleInspector
{
    ModuleListResult List(
        int processId,
        string? nameFilter,
        bool verifySignatures,
        CancellationToken cancellationToken);
}

/// <summary>Raised when a process's modules could not be read.</summary>
public sealed class ModuleQueryException : Exception
{
    public ModuleQueryException(string message) : base(message)
    {
    }

    public ModuleQueryException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
