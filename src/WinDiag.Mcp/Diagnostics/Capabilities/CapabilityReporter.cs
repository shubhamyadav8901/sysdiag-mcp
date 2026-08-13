using WinDiag.Mcp.Diagnostics.External;

namespace WinDiag.Mcp.Diagnostics.Capabilities;

/// <summary>How usable a tool is on this machine, right now.</summary>
public enum CapabilityStatus
{
    /// <summary>Fully usable.</summary>
    Available,

    /// <summary>Runs, but returns less than the whole truth. The reason says why.</summary>
    Degraded,

    /// <summary>Cannot run at all. The reason says what is missing.</summary>
    Unavailable
}

/// <summary>The state of one tool on this machine.</summary>
public sealed record ToolCapability(string Tool, string Backing, CapabilityStatus Status, string Detail);

/// <summary>Reports which tools can actually do their job here.</summary>
public interface ICapabilityReporter
{
    IReadOnlyList<ToolCapability> Describe();
}

/// <summary>
/// Answers "what can you actually see on this box?" before an investigation relies on an answer.
/// </summary>
/// <remarks>
/// The requirements table below is hand-maintained, which would normally invite drift as tools are
/// added. <c>CapabilityReporterTests.Covers_every_registered_tool</c> reflects over every
/// <c>[McpServerTool]</c> in the assembly and fails if the two disagree, so a new tool cannot be
/// shipped without declaring what it needs.
/// </remarks>
public sealed class CapabilityReporter : ICapabilityReporter
{
    /// <summary>What each tool needs in order to answer completely.</summary>
    /// <param name="Backing">Implementation, for the reader's benefit.</param>
    /// <param name="RequiredExecutable">External binary without which the tool cannot run at all.</param>
    /// <param name="ElevationNote">
    /// Set when running unelevated silently reduces coverage rather than failing. Null when elevation
    /// makes no difference.
    /// </param>
    /// <param name="RequiresElevation">
    /// True when the tool cannot run at all unelevated, as opposed to returning less. The distinction
    /// matters: <c>Degraded</c> tells the caller to distrust an empty result, <c>Unavailable</c> tells
    /// them not to bother calling.
    /// </param>
    internal sealed record Requirement(
        string Backing,
        string? RequiredExecutable,
        string? ElevationNote,
        bool RequiresElevation = false);

    internal static readonly IReadOnlyDictionary<string, Requirement> Requirements =
        new Dictionary<string, Requirement>(StringComparer.Ordinal)
        {
            ["who_locks_path"] = new("Windows Restart Manager", null, null),
            ["path_handle_search"] = new(
                "Sysinternals handle.exe",
                "handle.exe",
                "returns a partial list, silently omitting handles held by other users and by SYSTEM"),
            ["system_overview"] = new("Win32 and .NET runtime information", null, null),
            ["capabilities"] = new("this reporter", null, null),
            ["service_config"] = new("Service Control Manager and the services registry key", null, null),
            ["process_list"] = new(
                "WMI Win32_Process",
                null,
                "cannot read the command line of processes owned by other users, which are reported as null"),
            ["named_pipes"] = new("NtQueryDirectoryFile on the pipe device", null, null),
            ["network_owners"] = new("IP Helper extended connection tables", null, null),
            ["file_signatures"] = new("WinVerifyTrust and file version information", null, null),
            ["effective_access"] = new(
                "Win32 security descriptors plus a real access attempt",
                null,
                "cannot read the ACL of objects that deny READ_CONTROL to this account"),
            ["capture_dump"] = new(
                "dbghelp MiniDumpWriteDump",
                null,
                "can only dump processes owned by the current user; another user's or SYSTEM's will fail"),
            ["capture_activity"] = new(
                "Sysinternals Procmon, batch mode",
                "Procmon.exe",
                null,
                RequiresElevation: true),
            ["query_activity"] = new("streaming read of a saved capture", null, null),
            ["event_log_tail"] = new(
                "Windows EventLogReader",
                null,
                "cannot read the Security log; Application and System are unaffected")
        };

    private readonly IToolLocator _locator;
    private readonly IPrivilegeProbe _privileges;

    public CapabilityReporter(IToolLocator locator, IPrivilegeProbe privileges)
    {
        _locator = locator;
        _privileges = privileges;
    }

    public IReadOnlyList<ToolCapability> Describe()
    {
        var capabilities = new List<ToolCapability>(Requirements.Count);

        foreach (var (tool, requirement) in Requirements.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            capabilities.Add(Evaluate(tool, requirement));
        }

        return capabilities;
    }

    private ToolCapability Evaluate(string tool, Requirement requirement)
    {
        if (requirement.RequiredExecutable is { } executable && !_locator.TryResolve(executable, out _))
        {
            return new ToolCapability(
                tool,
                requirement.Backing,
                CapabilityStatus.Unavailable,
                $"{executable} is not installed on this machine.");
        }

        if (requirement.RequiresElevation && !_privileges.IsElevated)
        {
            return new ToolCapability(
                tool,
                requirement.Backing,
                CapabilityStatus.Unavailable,
                "Requires administrator rights and cannot run without them. Restart the server from an " +
                "elevated terminal.");
        }

        if (requirement.ElevationNote is { } note && !_privileges.IsElevated)
        {
            return new ToolCapability(
                tool,
                requirement.Backing,
                CapabilityStatus.Degraded,
                $"Not elevated, so this tool {note}. Restart the server from an elevated terminal.");
        }

        return new ToolCapability(tool, requirement.Backing, CapabilityStatus.Available, "Ready.");
    }
}
