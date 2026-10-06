namespace WinDiag.Mcp.Diagnostics.Modules;

/// <summary>One DLL or executable image loaded into a process.</summary>
/// <remarks>
/// <see cref="Path"/> is the loader's record of where the module came from, which the process itself keeps
/// and which NTFS lets go stale: a loaded DLL can be renamed, and another file put at its old path. So
/// nothing below is read from that path. The kernel names the file actually behind each module's mapping,
/// that file is held open against writes, renames and deletes, and version, preferred base and signature
/// are all read from it -- or from nothing, when it could not be identified.
/// </remarks>
/// <param name="FileVersion">
/// Read from the loaded image's own file. Null when that file could not be identified
/// (<see cref="ImageFileUnknownReason"/>), rather than the version of whatever sits at <see cref="Path"/>.
/// </param>
/// <param name="SignatureVerdict">
/// Null unless signature verification was requested. Otherwise the Authenticode verdict on the loaded
/// image's own file -- <c>Valid</c>, <c>Unsigned</c>, <c>Untrusted</c> or <c>Unknown</c> -- or
/// <c>NotVerified</c> when that file could not be identified, because a verdict on any other file says
/// nothing about the code that is running.
/// </param>
/// <param name="PreferredBase">
/// The <c>ImageBase</c> the loaded image's file asks for, read from its PE header. Null when the header
/// could not be read or the file could not be identified.
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
/// <param name="ReplacedOnDisk">
/// True when <see cref="Path"/> no longer names the loaded image's file: it names a different file (by
/// volume and file ID), or nothing at all. The image's file is then at <see cref="ImageFilePath"/>. Null
/// when that could not be settled -- the image's file was not identified, or the path is a network or
/// device path this server does not open, or opening it failed for a reason other than its not existing.
/// </param>
/// <param name="ImageFilePath">
/// Where the loaded image's file is now, when that is not <see cref="Path"/>.
/// </param>
/// <param name="ImageFileUnknownReason">
/// Why the file behind this module's mapping could not be identified and held. When set, nothing about
/// the module is read from any file: no version, no preferred base, and no signature verdict.
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
    bool BaseCollision = false,
    bool? ReplacedOnDisk = null,
    string? ImageFilePath = null,
    string? ImageFileUnknownReason = null)
{
    /// <summary>The verdict given to a module whose loaded image's file could not be identified.</summary>
    public const string NotVerified = "NotVerified";
}

/// <summary>Result of listing a process's loaded modules.</summary>
/// <param name="UnsignedCount">Returned modules whose loaded image's file is unsigned or untrusted.</param>
/// <param name="Limitation">
/// Set when the list is known to be incomplete — enumeration failed partway through, so what came back
/// is a prefix rather than the whole truth. Stated explicitly because a short module list looks exactly
/// like a process that has loaded very little. When nothing at all could be read the inspector throws
/// instead, so this never accompanies an empty list.
/// </param>
/// <param name="ReplacedCount">
/// Modules whose listed path no longer names the loaded image's file, counted over every match rather
/// than the returned page, so a replaced module cannot vanish from the count by sorting past the cap.
/// </param>
/// <param name="UnidentifiedCount">
/// Modules whose loaded image's file could not be identified, counted over every match for the same
/// reason.
/// </param>
/// <param name="NotVerifiedCount">
/// Returned modules that got no signature verdict because their loaded image's file could not be
/// identified. Never folded into a clean result: a module that could not be checked is not a signed one.
/// </param>
public sealed record ModuleListResult(
    int ProcessId,
    string ProcessName,
    IReadOnlyList<LoadedModule> Modules,
    int TotalMatched,
    bool Truncated,
    int UnsignedCount,
    string? Limitation,
    int CollisionCount = 0,
    int ReplacedCount = 0,
    int UnidentifiedCount = 0,
    int NotVerifiedCount = 0);

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
