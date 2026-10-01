namespace MacDiag.Mcp.Diagnostics.Services;

public enum ServiceAction
{
    Start,
    Stop,
    Restart,
}

/// <remarks>No dependents: launchd has no dependencies between jobs, so stopping one stops only it.</remarks>
public sealed record ServiceControlResult(string Label, ServiceAction Action, string StatusBefore, string StatusAfter, string Detail);

public interface IServiceController
{
    Task<ServiceControlResult> ControlAsync(string label, ServiceAction action, CancellationToken cancellationToken);
}

public sealed class ServiceControlException : Exception, IDiagnosticException
{
    public ServiceControlException(string message)
        : base(message)
    {
    }

    public ServiceControlException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
