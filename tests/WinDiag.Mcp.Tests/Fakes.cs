using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.Autostart;
using WinDiag.Mcp.Diagnostics.Control;
using WinDiag.Mcp.Diagnostics.External;
using WinDiag.Mcp.Diagnostics.Handles;
using WinDiag.Mcp.Diagnostics.Locks;

namespace WinDiag.Mcp.Tests;

internal sealed class FakePrivilegeProbe(bool isElevated) : IPrivilegeProbe
{
    public bool IsElevated { get; } = isElevated;
}

/// <summary>
/// Resolves a fixed set of tool names to a real binary of this machine's own architecture.
/// </summary>
/// <remarks>
/// The path has to be a genuine native image, not a placeholder: architecture-aware resolution reads
/// the PE machine type of whatever it resolves, and a fabricated path would either fail the read or --
/// worse, if pointed at a managed assembly, which is stamped I386 even when it runs 64-bit -- be
/// reported as the wrong architecture. <c>cmd.exe</c> from the system directory always matches the OS.
/// </remarks>
internal sealed class FakeToolLocator(params string[] resolvableNames) : IToolLocator
{
    private static readonly string NativeImage = Path.Combine(Environment.SystemDirectory, "cmd.exe");

    private readonly HashSet<string> _names = new(resolvableNames, StringComparer.OrdinalIgnoreCase);

    /// <summary>Every name asked for, so a test can assert which build was looked for first.</summary>
    public List<string> Requested { get; } = [];

    public string Resolve(string executableName) =>
        TryResolve(executableName, out var path) ? path : throw new ToolNotFoundException(executableName);

    public bool TryResolve(string executableName, out string fullPath)
    {
        Requested.Add(executableName);

        if (_names.Contains(executableName))
        {
            fullPath = NativeImage;
            return true;
        }

        fullPath = string.Empty;
        return false;
    }
}

/// <summary>
/// A machine where only the 32-bit build of a tool was staged.
/// </summary>
/// <remarks>
/// Points at the real <c>SysWOW64\cmd.exe</c>, which is genuinely an I386 image on 64-bit Windows, so
/// the PE machine check under test reads a true header rather than a fixture someone has to keep
/// honest. Resolves only the unsuffixed name, which is exactly the half-staged state this guards.
/// </remarks>
internal sealed class FixedArchitectureLocator(ushort machine) : IToolLocator
{
    private static readonly string ThirtyTwoBitImage =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64", "cmd.exe");

    public string Resolve(string executableName) =>
        TryResolve(executableName, out var path) ? path : throw new ToolNotFoundException(executableName);

    public bool TryResolve(string executableName, out string fullPath)
    {
        if (executableName.Contains("64", StringComparison.Ordinal))
        {
            fullPath = string.Empty;
            return false;
        }

        fullPath = machine == PeImageHeader.MachineI386
            ? ThirtyTwoBitImage
            : Path.Combine(Environment.SystemDirectory, "cmd.exe");

        return File.Exists(fullPath);
    }
}

internal sealed class FakeLockInspector(LockQueryResult result) : ILockInspector
{
    public LockQueryResult WhoLocks(string path, CancellationToken cancellationToken) =>
        result with { Path = path };
}

internal sealed class FakeHandleInspector(HandleSearchResult result) : IHandleInspector
{
    public bool? LastIncludeAllObjectTypes { get; private set; }
    public int? LastProcessId { get; private set; }

    public Task<HandleSearchResult> SearchAsync(
        string nameFragment,
        bool includeAllObjectTypes,
        CancellationToken cancellationToken)
    {
        LastIncludeAllObjectTypes = includeAllObjectTypes;
        return Task.FromResult(result);
    }

    public Task<HandleSearchResult> ListForProcessAsync(
        int processId,
        bool includeAllObjectTypes,
        CancellationToken cancellationToken)
    {
        LastProcessId = processId;
        LastIncludeAllObjectTypes = includeAllObjectTypes;
        return Task.FromResult(result);
    }
}

internal sealed class FakeAutostartInspector(AutostartAuditResult result) : IAutostartInspector
{
    public AutostartQuery? LastQuery { get; private set; }

    public Task<AutostartAuditResult> AuditAsync(AutostartQuery query, CancellationToken cancellationToken)
    {
        LastQuery = query;
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
internal sealed class StubExternalToolRunner(string standardOutput = "", int exitCode = 0, int? processId = null) : IExternalToolRunner
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
            executableName, argv, exitCode, standardOutput, string.Empty, TimeSpan.Zero, processId));
    }
}

/// <summary>
/// A process table that answers each snapshot from a fixed list of tables, the last repeating; by default
/// the given processes, created at time 1, running throughout.
/// </summary>
internal sealed class FakeProcessTable : IProcessTable
{
    private readonly IReadOnlyDictionary<int, ProcessImage>[] _snapshots;

    public FakeProcessTable(params (int ProcessId, string Image)[] processes)
        : this([processes.ToDictionary(p => p.ProcessId, p => new ProcessImage(1, p.Image))])
    {
    }

    public FakeProcessTable(IReadOnlyDictionary<int, ProcessImage>[] snapshots) => _snapshots = snapshots;

    public int Taken { get; private set; }

    public IReadOnlyDictionary<int, ProcessImage> Snapshot() => _snapshots[Math.Min(Taken++, _snapshots.Length - 1)];
}

/// <summary>Answers for a process's services and critical flag from fixed values, counting each question.</summary>
internal sealed class FakeProtectionProbe : IProcessProtectionProbe
{
    public Dictionary<int, IReadOnlyList<string>> Services { get; } = [];

    public bool Critical { get; init; }

    public Exception? ServicesFailure { get; init; }

    public int Calls { get; private set; }

    public IReadOnlyList<string> ServicesHostedBy(int processId)
    {
        Calls++;
        if (ServicesFailure is { } failure)
        {
            throw failure;
        }

        return Services.TryGetValue(processId, out var services) ? services : [];
    }

    public bool IsCritical(System.Diagnostics.Process process)
    {
        Calls++;
        return Critical;
    }
}
