using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Diagnostics.Access;

[Flags]
public enum AccessRights
{
    None = 0,
    Execute = 1,
    Write = 2,
    Read = 4,
}

/// <param name="Groups">Every group counted for the group class, the primary one included.</param>
/// <param name="DacOverride">CAP_DAC_OVERRIDE: read and write past the bits, execute where some class may.</param>
/// <param name="DacReadSearch">CAP_DAC_READ_SEARCH: read files, and read and search directories, past the bits.</param>
public sealed record AccessSubject(
    string Description, uint UserId, string? UserName, IReadOnlyList<uint> Groups, bool DacOverride, bool DacReadSearch);

/// <param name="Permissions">The nine rwx bits. With an ACL the group bits are the mask, and the ACL decides.</param>
/// <param name="IsRegular">A regular file: only these are refused by noexec, and a device, FIFO or socket ignores a read-only mount.</param>
public sealed record FileFacts(
    uint Owner, uint Group, int Permissions, bool IsDirectory, IReadOnlyList<AclEntry>? Acl, bool Immutable, bool AppendOnly,
    bool ReadOnlyMount, bool NoExecMount, bool IsRegular);

public sealed record AccessDecision(bool Allowed, string Reason);

/// <param name="CanSearch">Whether the subject may pass through this directory (its x bit, for them).</param>
public sealed record PathStep(string Path, bool CanSearch, string Reason);

/// <summary>The kernel's own faccessat answer, for the server's credentials.</summary>
/// <param name="SameSubject">The subject evaluated is the server's own credentials, so the two answers must agree.</param>
public sealed record ServerProbe(uint UserId, bool Read, bool Write, bool Execute, bool SameSubject);

/// <param name="ResolvedPath">Where the path leads once links are followed; null when it is the file itself.</param>
/// <param name="Mode">Octal and symbolic: "0640 rw-r-----".</param>
/// <param name="DefaultAcl">A directory's default ACL: what new entries in it inherit.</param>
/// <param name="FileCapabilities">What executing the file grants (getcap's notation), when it carries any.</param>
/// <param name="BlockedAt">The first directory on the way the subject cannot search.</param>
public sealed record EffectiveAccessReport(
    string Path, string? ResolvedPath, string Kind, string Owner, string Group, string Mode, IReadOnlyList<string> Acl,
    IReadOnlyList<string> DefaultAcl, string? FileCapabilities, bool Immutable, bool AppendOnly, string? MountPoint,
    IReadOnlyList<string> MountOptions, AccessSubject Subject, AccessDecision Read, AccessDecision Write,
    AccessDecision Execute, IReadOnlyList<PathStep> Traversal, string? BlockedAt, ServerProbe Probe, IReadOnlyList<string> Notes);

public interface IAccessInspector
{
    EffectiveAccessReport Inspect(string path, string? account, int? processId);
}

public sealed class AccessInspectionException : Exception, IDiagnosticException
{
    public AccessInspectionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
