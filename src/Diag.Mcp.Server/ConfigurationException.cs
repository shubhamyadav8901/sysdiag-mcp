namespace Diag.Mcp.Server;

/// <summary>Raised when the environment configures the server into an unusable state.</summary>
/// <remarks>Fails fast at startup rather than surfacing as a confusing failure on the first tool call.</remarks>
public sealed class ConfigurationException : Exception
{
    public ConfigurationException(string message) : base(message)
    {
    }
}
