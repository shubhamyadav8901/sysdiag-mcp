namespace WinDiag.Mcp.Diagnostics.Control;

/// <summary>What to do to a service.</summary>
public enum ServiceAction
{
    Start,
    Stop,
    Restart
}

/// <summary>Outcome of acting on a service.</summary>
public sealed record ServiceControlResult(
    string ServiceName,
    string? DisplayName,
    ServiceAction Action,
    string StatusBefore,
    string StatusAfter,
    IReadOnlyList<string> DependentServicesStopped,
    string Detail);

/// <summary>Starts, stops and restarts Windows services.</summary>
public interface IServiceController
{
    ServiceControlResult Control(string serviceName, ServiceAction action, CancellationToken cancellationToken);
}

/// <summary>Raised when an action on a service is refused or fails.</summary>
public sealed class ServiceControlException : Exception
{
    public ServiceControlException(string message) : base(message)
    {
    }

    public ServiceControlException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
