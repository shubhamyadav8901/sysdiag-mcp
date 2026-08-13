using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.External;
using WinDiag.Mcp.Diagnostics.Handles;
using WinDiag.Mcp.Diagnostics.Locks;

namespace WinDiag.Mcp.Tests;

internal sealed class FakePrivilegeProbe(bool isElevated) : IPrivilegeProbe
{
    public bool IsElevated { get; } = isElevated;
}

internal sealed class FakeLockInspector(LockQueryResult result) : ILockInspector
{
    public LockQueryResult WhoLocks(string path, CancellationToken cancellationToken) =>
        result with { Path = path };
}

internal sealed class FakeHandleInspector(HandleSearchResult result) : IHandleInspector
{
    public bool? LastIncludeAllObjectTypes { get; private set; }

    public Task<HandleSearchResult> SearchAsync(
        string nameFragment,
        bool includeAllObjectTypes,
        CancellationToken cancellationToken)
    {
        LastIncludeAllObjectTypes = includeAllObjectTypes;
        return Task.FromResult(result);
    }
}

/// <summary>
/// Records the argument vector each invocation would have used, and returns canned output.
/// </summary>
/// <remarks>
/// Asserting on <see cref="Invocations"/> is how the suite proves that no destructive switch can be
/// composed -- checking the parsed result alone would pass even if the wrong flags were sent.
/// </remarks>
internal sealed class StubExternalToolRunner(string standardOutput = "", int exitCode = 0) : IExternalToolRunner
{
    public List<(string Executable, IReadOnlyList<string> Arguments)> Invocations { get; } = [];

    public Task<ExternalToolResult> RunAsync(
        string executableName,
        IReadOnlyList<ToolArgument> arguments,
        ExternalToolPolicy policy,
        CancellationToken cancellationToken)
    {
        // Run the real vector builder, with the real policy, so the guard and the per-tool prefix are
        // both exercised on the same path production uses.
        var argv = ExternalToolRunner.BuildArgumentVector(arguments, policy.StandardArguments);
        Invocations.Add((executableName, argv));

        return Task.FromResult(new ExternalToolResult(
            executableName, argv, exitCode, standardOutput, string.Empty, TimeSpan.Zero));
    }
}
