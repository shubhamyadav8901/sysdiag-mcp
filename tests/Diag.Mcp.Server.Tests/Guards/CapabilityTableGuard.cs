using System.Reflection;
using Diag.Mcp.Server.Capabilities;
using ModelContextProtocol.Server;

namespace Diag.Mcp.Server.Tests;

/// <summary>A server's capability table must name every tool it and the kit declare, and nothing else.</summary>
/// <remarks>
/// The table is hand-maintained, so without this it would quietly fall behind as tools are added -- and
/// capabilities would then confidently report on a subset while the caller believed it was seeing
/// everything. Reflects over every assembly given, because a guard over one assembly stops covering a
/// tool the moment it moves into another.
/// </remarks>
public static class CapabilityTableGuard
{
    public static IReadOnlyList<string> DeclaredToolNames(params Assembly[] assemblies) =>
        assemblies
            .SelectMany(assembly => assembly.GetTypes())
            .Where(type => type.GetCustomAttribute<McpServerToolTypeAttribute>() is not null)
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            .Select(method => method.GetCustomAttribute<McpServerToolAttribute>())
            .Where(attribute => attribute?.Name is not null)
            .Select(attribute => attribute!.Name!)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

    public static void AssertTableMatchesDeclaredTools(
        IReadOnlyDictionary<string, CapabilityRequirement> table, params Assembly[] assemblies)
    {
        ArgumentNullException.ThrowIfNull(table);
        Assert.Equal(DeclaredToolNames(assemblies), table.Keys.OrderBy(name => name, StringComparer.Ordinal));
    }
}
