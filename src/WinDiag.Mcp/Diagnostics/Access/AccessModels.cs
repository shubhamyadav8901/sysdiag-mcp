namespace WinDiag.Mcp.Diagnostics.Access;

/// <summary>What kind of securable object was inspected.</summary>
public enum SecurableKind
{
    File,
    Directory,
    RegistryKey
}

/// <summary>One access control entry from an object's DACL.</summary>
public sealed record AccessRule(
    string Identity,
    string Rights,
    string Type,
    bool Inherited);

/// <summary>
/// Result of actually attempting access, as opposed to reasoning about the ACL.
/// </summary>
/// <remarks>
/// The empirical answer settles arguments the ACL alone cannot: share modes, integrity levels,
/// filter drivers and privileges all affect the outcome without appearing in a single ACE.
/// </remarks>
public sealed record AccessProbe(bool? CanRead, bool? CanWrite, string? ReadError, string? WriteError);

/// <summary>Everything known about who may do what to one object.</summary>
/// <param name="Account">The account asked about, if any.</param>
/// <param name="RulesForAccount">
/// ACEs naming that account directly. Note this is not the same as effective rights: rights granted
/// via group membership are not resolved, which is stated plainly in the rendered output rather than
/// silently implied.
/// </param>
public sealed record AccessReport(
    string Path,
    SecurableKind Kind,
    string? Owner,
    IReadOnlyList<AccessRule> Rules,
    string? Account,
    IReadOnlyList<AccessRule> RulesForAccount,
    AccessProbe Probe,
    string ProbeIdentity);

/// <summary>Inspects the security descriptor of files, folders and registry keys.</summary>
public interface IAccessInspector
{
    AccessReport Inspect(string path, string? account, bool probeWrite, CancellationToken cancellationToken);
}

/// <summary>Raised when an object's security information could not be read.</summary>
public sealed class AccessQueryException : Exception
{
    public AccessQueryException(string message) : base(message)
    {
    }

    public AccessQueryException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
