using System.ComponentModel;
using System.Text;
using ModelContextProtocol.Server;

namespace Diag.Mcp.Server.Capabilities;

/// <summary>Structured result of <c>capabilities</c>.</summary>
public sealed record CapabilitiesResult(
    string Summary,
    bool Elevated,
    IReadOnlyList<ToolCapability> Tools);

/// <summary>The <c>capabilities</c> tool: what can this server actually see on this machine.</summary>
/// <remarks>
/// Shared, with the rules in <see cref="CapabilityReporter"/>; what a server's tools need is its own
/// <see cref="ICapabilityRequirements"/>. The description is compile-time text served by every server,
/// so it names no platform's helper programs.
/// </remarks>
[McpServerToolType]
public sealed class CapabilityTools
{
    private readonly ICapabilityReporter _capabilities;
    private readonly IPrivilegeProbe _privileges;

    public CapabilityTools(ICapabilityReporter capabilities, IPrivilegeProbe privileges)
    {
        _capabilities = capabilities;
        _privileges = privileges;
    }

    [McpServerTool(
        Name = "capabilities",
        Title = "Server capabilities",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Report which of this server's tools can actually answer completely on this machine, and why " +
        "any cannot - a missing helper program, or a tool that silently returns partial results " +
        "because the server is not elevated. Call this when a result looks surprisingly empty, before " +
        "concluding that nothing was found.")]
    public CapabilitiesResult Capabilities()
    {
        var capabilities = _capabilities.Describe();

        // The probe, not the full system overview: the overview's Elevated is this same probe, and
        // the rest of it -- disks, memory, uptime -- is not what this call is asking about.
        var elevated = _privileges.IsElevated;

        return new CapabilitiesResult(RenderCapabilities(capabilities, elevated), elevated, capabilities);
    }

    internal static string RenderCapabilities(IReadOnlyList<ToolCapability> capabilities, bool elevated)
    {
        var builder = new StringBuilder();

        var unavailable = capabilities.Count(c => c.Status == CapabilityStatus.Unavailable);
        var degraded = capabilities.Count(c => c.Status == CapabilityStatus.Degraded);

        builder.Append(capabilities.Count).Append(" tools; ")
            .Append(capabilities.Count - unavailable - degraded).Append(" fully available");

        if (degraded > 0)
        {
            builder.Append(", ").Append(degraded).Append(" degraded");
        }

        if (unavailable > 0)
        {
            builder.Append(", ").Append(unavailable).Append(" unavailable");
        }

        builder.Append(". Server is ").Append(elevated ? "elevated." : "NOT elevated.").AppendLine();

        foreach (var capability in capabilities)
        {
            builder.Append("- ").Append(capability.Tool).Append(" [").Append(capability.Status).Append("] ")
                .Append(capability.Backing);

            if (capability.Status != CapabilityStatus.Available)
            {
                builder.Append(" - ").Append(capability.Detail);
            }

            builder.AppendLine();
        }

        return builder.ToString().TrimEnd();
    }
}
