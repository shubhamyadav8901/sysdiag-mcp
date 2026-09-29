namespace Diag.Mcp.Core;

/// <summary>
/// Marks an exception whose message is written for the caller: a diagnosis, not a defect.
/// </summary>
/// <remarks>
/// The call-tool filter reports a marked exception verbatim and hides everything else, whose messages
/// can carry internals that are no use to a caller and unwise to publish over a network endpoint.
/// Implement it on any exception a tool throws on purpose to explain why it refused.
/// </remarks>
public interface IDiagnosticException
{
}
