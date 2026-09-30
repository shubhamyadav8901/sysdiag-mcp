using System.Runtime.Versioning;
using Diag.Mcp.Server.Capabilities;

namespace Diag.Mcp.Server.External;

/// <summary>Finds a program only where the runner will take it from, so capabilities never promise one the runner refuses.</summary>
[UnsupportedOSPlatform("windows")]
public sealed class SystemExecutableResolver(IReadOnlyList<string> directories) : IExecutableResolver
{
    public ExecutableResolution Resolve(string baseName) =>
        SystemCommand.Resolve(baseName, directories) is { } path
            ? new ExecutableResolution(path, null)
            : new ExecutableResolution(null, $"'{baseName}' is not installed on this machine: it is in none of {string.Join(", ", directories)}.");
}
