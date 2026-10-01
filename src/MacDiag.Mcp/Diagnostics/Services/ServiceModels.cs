namespace MacDiag.Mcp.Diagnostics.Services;

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
