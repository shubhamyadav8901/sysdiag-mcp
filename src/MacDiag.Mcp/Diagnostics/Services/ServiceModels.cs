namespace MacDiag.Mcp.Diagnostics.Services;

/// <param name="Domain">Where launchd has the job: "system", "gui/&lt;uid&gt;", or where it would be when not loaded.</param>
/// <param name="Status">launchctl's state ("running", "not running", "waiting"), or "not loaded".</param>
/// <param name="KeepAlive">"true", "false", or "when: Key=value, …" for a KeepAlive dictionary; null when unset.</param>
/// <param name="Disabled">launchd's override (launchctl print-disabled), else the plist's Disabled key; null when neither says.</param>
/// <param name="Limitations">What could not be read, so a null is never mistaken for "none".</param>
public sealed record ServiceInfo(
    string Label, string Domain, string? PlistPath, string Status, int? MainProcessId, int? LastExitStatus, string? LastExitText,
    int? Runs, string? Program, IReadOnlyList<string> Arguments, bool RunAtLoad, string? KeepAlive, string? Account, bool? Disabled,
    IReadOnlyList<string> Limitations);

public sealed record ServiceQueryResult(string Query, ServiceInfo? Service, IReadOnlyList<string> Candidates);

public interface IServiceInspector
{
    Task<ServiceQueryResult> QueryAsync(string label, CancellationToken cancellationToken);
}

public sealed class ServiceQueryException : Exception, IDiagnosticException
{
    public ServiceQueryException(string message)
        : base(message)
    {
    }

    public ServiceQueryException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
