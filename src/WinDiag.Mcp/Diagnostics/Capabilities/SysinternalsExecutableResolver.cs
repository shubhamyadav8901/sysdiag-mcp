using System.Runtime.Versioning;
using Diag.Mcp.Server.Capabilities;
using WinDiag.Mcp.Diagnostics.External;

namespace WinDiag.Mcp.Diagnostics.Capabilities;

/// <summary>Resolves a Sysinternals tool the same way the tool itself will when it is called.</summary>
/// <remarks>
/// The same architecture decision the tools make, so <c>capabilities</c> cannot report Available for a
/// build the tool would then refuse -- or Unavailable because only the correctly-suffixed build is
/// present.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class SysinternalsExecutableResolver : IExecutableResolver
{
    /// <summary>
    /// Generic stand-in for the per-tool symptom text.
    /// </summary>
    /// <remarks>
    /// The tools themselves pass what their own 32-bit build actually does wrong, because that is what
    /// makes the refusal actionable. This report only needs to say the build is unusable; if a caller
    /// wants the detail they will get it the moment they call the tool.
    /// </remarks>
    private const string ArchitectureSymptom =
        "it returns an empty or truncated answer rather than failing, which reads as a clean result.";

    private readonly IToolLocator _locator;

    public SysinternalsExecutableResolver(IToolLocator locator)
    {
        _locator = locator;
    }

    public ExecutableResolution Resolve(string baseName)
    {
        var choice = SysinternalsArchitecture.Choose(_locator, baseName, ArchitectureSymptom);
        return choice.ExecutableName is null ? new(null, choice.Problem) : new(choice.Path, null);
    }
}
