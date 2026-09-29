namespace WinDiag.Mcp.Diagnostics.Modules;

/// <summary>One DLL or executable image loaded into a process.</summary>
/// <param name="SignatureVerdict">Null unless signature verification was requested.</param>
/// <param name="PreferredBase">
/// The <c>ImageBase</c> the file on disk asks for, read from its PE header. Null when the header could
/// not be read.
/// </param>
/// <param name="Relocated">
/// True when the module did not get the base it asked for. Null when <see cref="PreferredBase"/> is
/// unknown. On its own this means very little — ASLR moves nearly every system image every boot — so
/// see <see cref="BaseCollision"/> for the case that is actually worth reading.
/// </param>
/// <param name="BaseCollision">
/// True when the image did <em>not</em> opt into ASLR (no <c>IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE</c>)
/// and was moved anyway. That only happens when something already occupied its preferred range, which
/// costs the module its shareable pages and is a real finding rather than routine hardening.
/// </param>
public sealed record LoadedModule(
    string Name,
    string Path,
    string BaseAddress,
    long SizeBytes,
    string? FileVersion,
    string? CompanyName,
    string? SignatureVerdict,
    string? Signer,
    string? PreferredBase = null,
    bool? Relocated = null,
    bool BaseCollision = false);

/// <summary>Result of listing a process's loaded modules.</summary>
/// <param name="Limitation">
/// Set when the list is known to be incomplete — enumeration failed partway through, so what came back
/// is a prefix rather than the whole truth. Stated explicitly because a short module list looks exactly
/// like a process that has loaded very little. When nothing at all could be read the inspector throws
/// instead, so this never accompanies an empty list.
/// </param>
public sealed record ModuleListResult(
    int ProcessId,
    string ProcessName,
    IReadOnlyList<LoadedModule> Modules,
    int TotalMatched,
    bool Truncated,
    int UnsignedCount,
    string? Limitation,
    int CollisionCount = 0);

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
public sealed class ModuleQueryException : Exception, IDiagnosticException
{
    public ModuleQueryException(string message) : base(message)
    {
    }

    public ModuleQueryException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
