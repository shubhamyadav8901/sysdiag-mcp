namespace LinuxDiag.Mcp.Diagnostics.Services;

public enum ServiceAction
{
    Start,
    Stop,
    Restart,
}

/// <param name="DependentServicesStopped">Services that were active and stopped with it; restarting this one does not bring them back.</param>
public sealed record ServiceControlResult(
    string ServiceName, string? DisplayName, ServiceAction Action, string StatusBefore, string StatusAfter,
    IReadOnlyList<string> DependentServicesStopped, string Detail);

public interface IServiceController
{
    Task<ServiceControlResult> ControlAsync(string serviceName, ServiceAction action, CancellationToken cancellationToken);
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
