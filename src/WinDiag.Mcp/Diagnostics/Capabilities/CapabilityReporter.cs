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
    /// <param name="RequiredExecutable">
    /// Sysinternals tool without which this cannot run at all, given as the BASE name -- <c>handle</c>,
    /// not <c>handle.exe</c>. The bitness suffix is not part of the requirement because which build is
    /// correct depends on the machine being asked, and reporting on the wrong one is how a target ends
    /// up running a build that answers "nothing found" to everything.
    /// </param>
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
                "handle",
                "returns a partial list, silently omitting handles held by other users and by SYSTEM"),
            ["process_handles"] = new(
                "Sysinternals handle.exe, scoped to one process",
                "handle",
                "returns a partial list, silently omitting handles the current account cannot see"),
            ["autostart_audit"] = new(
                "Sysinternals autorunsc",
                "autorunsc",
                "cannot read other users' profiles or protected keys, so entries are silently absent"),
            ["registry_read"] = new(
                "managed registry API, native view",
                null,
                @"cannot read keys that deny read access to this account, such as parts of HKLM\SECURITY"),
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
                "Procmon",
                null,
                RequiresElevation: true),
            ["query_activity"] = new("streaming read of a saved capture", null, null),
            ["process_modules"] = new(
                "managed process module list, PE headers and WinVerifyTrust",
                null,
                "cannot read modules of processes owned by other users"),
            ["process_control"] = new(
                "Win32 process control",
                null,
                "can only act on processes owned by the current user"),
            ["service_control"] = new(
                "Service Control Manager",
                null,
                "cannot start or stop most services without administrator rights",
                RequiresElevation: false),
            ["update_self"] = new(
                "hash-verified replacement of this server's own executable",
                null,
                "cannot replace a binary in a protected location without administrator rights",
                RequiresElevation: false),
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
        string? resolvedPath = null;

        if (requirement.RequiredExecutable is { } baseName)
        {
            // Same decision the tool itself will make when called, so this cannot report Available for
            // a build the tool would then refuse -- or Unavailable because only the correctly-suffixed
            // build is present.
            var choice = SysinternalsArchitecture.Choose(_locator, baseName, ArchitectureSymptom);

            if (choice.ExecutableName is null)
            {
                return new ToolCapability(
                    tool, requirement.Backing, CapabilityStatus.Unavailable, choice.Problem!);
            }

            resolvedPath = choice.Path;
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

        // Naming the resolved path answers the question this report exists for: not "is a copy of
        // handle.exe somewhere on this machine" but "which one will you run". Two copies of a
        // Sysinternals tool on one box is the normal case, not the exotic one.
        return new ToolCapability(
            tool,
            requirement.Backing,
            CapabilityStatus.Available,
            resolvedPath is null ? "Ready." : $"Ready, using {resolvedPath}.");
    }

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
}
