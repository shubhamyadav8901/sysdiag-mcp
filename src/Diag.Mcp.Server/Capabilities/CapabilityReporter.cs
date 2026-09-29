namespace Diag.Mcp.Server.Capabilities;

/// <summary>
/// Answers "what can you actually see on this box?" before an investigation relies on an answer.
/// </summary>
/// <remarks>
/// The rules are shared; the table, the executable resolver and the privilege probe are each server's.
/// A server's table is hand-maintained, which would normally invite drift as tools are added, so each
/// server's suite reflects over every <c>[McpServerTool]</c> it registers -- its own and the kit's --
/// and fails if the two disagree. A new tool cannot be shipped without declaring what it needs.
/// </remarks>
public sealed class CapabilityReporter : ICapabilityReporter
{
    private readonly IReadOnlyDictionary<string, CapabilityRequirement> _requirements;
    private readonly IExecutableResolver _resolver;
    private readonly IPrivilegeProbe _privileges;

    public CapabilityReporter(
        ICapabilityRequirements requirements, IExecutableResolver resolver, IPrivilegeProbe privileges)
    {
        ArgumentNullException.ThrowIfNull(requirements);
        _requirements = requirements.Requirements;
        _resolver = resolver;
        _privileges = privileges;
    }

    public IReadOnlyList<ToolCapability> Describe()
    {
        var capabilities = new List<ToolCapability>(_requirements.Count);

        foreach (var (tool, requirement) in _requirements.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            capabilities.Add(Evaluate(tool, requirement));
        }

        return capabilities;
    }

    private ToolCapability Evaluate(string tool, CapabilityRequirement requirement)
    {
        string? resolvedPath = null;

        if (requirement.RequiredExecutable is { } baseName)
        {
            // Same decision the tool itself will make when called, so this cannot report Available for
            // a build the tool would then refuse -- or Unavailable because only the correctly-suffixed
            // build is present.
            var resolution = _resolver.Resolve(baseName);

            if (resolution.Path is null)
            {
                return new ToolCapability(
                    tool, requirement.Backing, CapabilityStatus.Unavailable, resolution.Problem!);
            }

            resolvedPath = resolution.Path;
        }

        if (requirement.RequiresElevation && !_privileges.IsElevated)
        {
            return new ToolCapability(
                tool,
                requirement.Backing,
                CapabilityStatus.Unavailable,
                $"Requires {_privileges.PrivilegeName} and cannot run without them. {_privileges.HowToElevate}");
        }

        if (requirement.ElevationNote is { } note && !_privileges.IsElevated)
        {
            return new ToolCapability(
                tool,
                requirement.Backing,
                CapabilityStatus.Degraded,
                $"Not elevated, so this tool {note}. {_privileges.HowToElevate}");
        }

        // Naming the resolved path answers the question this report exists for: not "is a copy of
        // handle.exe somewhere on this machine" but "which one will you run". Two copies of a
        // helper tool on one box is the normal case, not the exotic one.
        return new ToolCapability(
            tool,
            requirement.Backing,
            CapabilityStatus.Available,
            resolvedPath is null ? "Ready." : $"Ready, using {resolvedPath}.");
    }
}
