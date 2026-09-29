using System.Reflection;

namespace Diag.Mcp.Server.Tests;

/// <summary>The guard itself, shared so each server's suite applies it to its own assembly.</summary>
/// <remarks>
/// A separate class because xUnit rejects a public non-test method on a test class, and in its own file
/// because each server's suite compiles the Guards folder in.
/// </remarks>
public static class DiagnosticExceptionGuard
{
    /// <summary>Thrown only before any transport exists, so they can never reach a tool call.</summary>
    /// <remarks>
    /// By full name: a short name would silently exempt any future type called ConfigurationException,
    /// in any namespace, and reopen exactly the drift the marker was introduced to end.
    /// </remarks>
    private static readonly string[] NeverReachesACaller = ["Diag.Mcp.Server.ConfigurationException"];

    /// <summary>Fails naming every exception in the given assemblies that is neither marked nor exempt.</summary>
    public static void AssertMarked(params Assembly[] assemblies)
    {
        var unmarked = assemblies
            .SelectMany(a => a.GetTypes())
            .Where(t => typeof(Exception).IsAssignableFrom(t) && !t.IsAbstract)
            .Where(t => !typeof(IDiagnosticException).IsAssignableFrom(t))
            .Where(t => !NeverReachesACaller.Contains(t.FullName))
            .Select(t => t.FullName)
            .ToArray();

        Assert.Empty(unmarked);
    }
}
