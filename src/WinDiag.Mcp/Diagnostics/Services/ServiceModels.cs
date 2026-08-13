namespace WinDiag.Mcp.Diagnostics.Services;

/// <summary>Configuration and live state of one Windows service.</summary>
/// <remarks>
/// Configuration comes from <c>HKLM\SYSTEM\CurrentControlSet\Services</c> and live state from the SCM.
/// Keeping those two sources distinct matters: "configured to start automatically" and "is running"
/// disagree in exactly the situations worth investigating.
/// </remarks>
public sealed record ServiceInfo(
    string ServiceName,
    string? DisplayName,
    string? Description,
    string Status,
    string StartType,
    bool DelayedAutoStart,
    string ServiceType,
    string? ImagePath,
    string? Account,
    IReadOnlyList<string> DependsOn,
    IReadOnlyList<string> DependedOnBy);

/// <summary>Outcome of a service lookup.</summary>
/// <param name="Service">The matched service, or null when nothing matched exactly.</param>
/// <param name="Candidates">
/// Near matches by substring, offered when the exact lookup failed. A typo'd service name is the most
/// common reason for an empty answer, and guessing again blindly is a poor use of a round trip.
/// </param>
public sealed record ServiceQueryResult(string Query, ServiceInfo? Service, IReadOnlyList<string> Candidates);

/// <summary>Reads Windows service configuration and state.</summary>
public interface IServiceInspector
{
    ServiceQueryResult Query(string nameOrDisplayName, CancellationToken cancellationToken);
}
