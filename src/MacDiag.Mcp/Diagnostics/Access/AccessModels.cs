namespace MacDiag.Mcp.Diagnostics.Access;

/// <param name="Groups">The account's groups by name, from the account database.</param>
public sealed record AccessSubject(string Description, uint UserId, string? UserName, IReadOnlyList<string> Groups);

/// <param name="Allowed">The kernel's answer; null when it could not be asked, never a guess.</param>
public sealed record AccessDecision(bool? Allowed, string Reason);

/// <param name="CanSearch">Whether the subject may pass through this directory; null when it could not be asked.</param>
public sealed record PathStep(string Path, bool? CanSearch, string Reason);

/// <summary>The kernel's own answer for the server's credentials.</summary>
/// <param name="SameSubject">The subject evaluated is the server's own account, so the two answers are one.</param>
public sealed record ServerProbe(uint UserId, bool? Read, bool? Write, bool? Execute, bool SameSubject);

/// <param name="ResolvedPath">Where the path leads once links are followed; null when it is the file itself.</param>
/// <param name="Mode">Octal and symbolic: "0640 rw-r-----".</param>
/// <param name="Acl">The ACL entries ls -le prints, in order: "group:everyone deny delete".</param>
/// <param name="Flags">chflags(1) flags: uchg, schg, restricted, uappnd...</param>
/// <param name="BlockedAt">The first directory on the way the subject cannot search.</param>
public sealed record EffectiveAccessReport(
    string Path, string? ResolvedPath, string Kind, string Owner, string Group, string Mode, IReadOnlyList<string> Acl,
    IReadOnlyList<string> Flags, string? MountPoint, IReadOnlyList<string> MountOptions, AccessSubject Subject,
    AccessDecision Read, AccessDecision Write, AccessDecision Execute, IReadOnlyList<PathStep> Traversal, string? BlockedAt,
    ServerProbe Probe, IReadOnlyList<string> Notes);

public interface IAccessInspector
{
    Task<EffectiveAccessReport> InspectAsync(string path, string? account, int? processId, CancellationToken cancellationToken);
}

public sealed class AccessInspectionException : Exception, IDiagnosticException
{
    public AccessInspectionException(string message)
        : base(message)
    {
    }

    public AccessInspectionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
