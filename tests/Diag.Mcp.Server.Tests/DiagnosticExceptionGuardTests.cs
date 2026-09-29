using System.Reflection;

namespace Diag.Mcp.Server.Tests;

/// <summary>
/// Every exception written for the caller must say so, in every assembly that can throw into a tool.
/// </summary>
/// <remarks>
/// Replaces a hand-maintained list that had already silently missed two types. A type that does not
/// implement IDiagnosticException reaches a caller as "An error occurred invoking 'x'.", with the
/// sentence that would have told them what to do discarded.
/// </remarks>
public sealed class DiagnosticExceptionGuardTests
{
    [Fact]
    public void Every_exception_the_core_and_the_kit_define_is_marked_or_declared_internal()
    {
        DiagnosticExceptionGuard.AssertMarked(typeof(PathScope).Assembly, typeof(DiagServerKit).Assembly);
    }

    [Fact]
    public void A_marked_exception_is_reported_and_an_unmarked_one_is_not()
    {
        Assert.True(ToolErrorTranslation.IsDiagnostic(new FileTransferException("x")));
        Assert.True(ToolErrorTranslation.IsDiagnostic(new ArgumentException("x")));
        Assert.True(ToolErrorTranslation.IsDiagnostic(new FormatException("x")));
        Assert.False(ToolErrorTranslation.IsDiagnostic(new InvalidOperationException("internals")));
    }
}

/// <summary>The guard itself, shared so each server's suite applies it to its own assembly.</summary>
/// <remarks>A separate class because xUnit rejects a public non-test method on a test class.</remarks>
public static class DiagnosticExceptionGuard
{
    /// <summary>Thrown only before any transport exists, so they can never reach a tool call.</summary>
    private static readonly string[] NeverReachesACaller = ["ConfigurationException"];

    /// <summary>Fails naming every exception in the given assemblies that is neither marked nor exempt.</summary>
    public static void AssertMarked(params Assembly[] assemblies)
    {
        var unmarked = assemblies
            .SelectMany(a => a.GetTypes())
            .Where(t => typeof(Exception).IsAssignableFrom(t) && !t.IsAbstract)
            .Where(t => !typeof(IDiagnosticException).IsAssignableFrom(t))
            .Where(t => !NeverReachesACaller.Contains(t.Name))
            .Select(t => t.FullName)
            .ToArray();

        Assert.Empty(unmarked);
    }
}
