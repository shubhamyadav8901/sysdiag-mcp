namespace LinuxDiag.Mcp.Diagnostics.Services;

/// <param name="DisplayName">systemd's Description=, the human name windiag calls DisplayName.</param>
/// <param name="Status">ActiveState and SubState, e.g. "active (running)" or "failed (failed)".</param>
/// <param name="StartType">UnitFileState: enabled, disabled, static, masked, generated, indirect…</param>
/// <param name="ServiceType">Type=: simple, notify, forking, oneshot…</param>
/// <param name="ImagePath">The first ExecStart command line, variables unexpanded.</param>
/// <param name="DependsOn">Requires=, BindsTo= and Requisite=: units it cannot run without.</param>
/// <param name="DependedOnBy">RequiredBy=, BoundBy=, RequisiteOf= and ConsistsOf=: units that stop when it stops.</param>
/// <param name="WeakDependsOn">Wants=: units it pulls in but runs without.</param>
/// <param name="LoadError">Why the unit file could not be loaded, as systemd put it; null when it loaded.</param>
/// <param name="WantedBy">WantedBy=: units that pull it in but keep running when it stops.</param>
public sealed record ServiceInfo(
    string ServiceName, string? DisplayName, string Status, string StartType, string ServiceType, string? ImagePath,
    string? Account, IReadOnlyList<string> DependsOn, IReadOnlyList<string> DependedOnBy, string LoadState,
    int? MainProcessId, string? Restart, int RestartCount, string? Result, string? FragmentPath,
    IReadOnlyList<string> DropIns, int? LastExitStatus, DateTimeOffset? ActiveSince, IReadOnlyList<string> WeakDependsOn,
    IReadOnlyList<string> WantedBy, string? LoadError);

public sealed record ServiceQueryResult(string Query, ServiceInfo? Service, IReadOnlyList<string> Candidates);

public interface IServiceInspector
{
    Task<ServiceQueryResult> QueryAsync(string name, CancellationToken cancellationToken);

    /// <summary>Up to 15 services whose name or description contains the query, for a name that did not match.</summary>
    Task<IReadOnlyList<string>> CandidatesAsync(string query, CancellationToken cancellationToken);
}
