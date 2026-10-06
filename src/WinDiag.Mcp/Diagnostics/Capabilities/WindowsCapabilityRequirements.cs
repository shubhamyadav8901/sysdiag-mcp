using Diag.Mcp.Server.Capabilities;

namespace WinDiag.Mcp.Diagnostics.Capabilities;

/// <summary>What each of this server's tools needs in order to answer completely.</summary>
/// <remarks>
/// Hand-maintained, which would normally invite drift as tools are added.
/// <c>CapabilityReporterTests.Covers_every_registered_tool_and_invents_none</c> reflects over every
/// <c>[McpServerTool]</c> in this assembly and the kit's, and fails if the two disagree, so a new tool
/// cannot be shipped without declaring what it needs. A <c>RequiredExecutable</c> here is a
/// Sysinternals base name, resolved by <see cref="SysinternalsExecutableResolver"/>.
/// </remarks>
public sealed class WindowsCapabilityRequirements : ICapabilityRequirements
{
    public IReadOnlyDictionary<string, CapabilityRequirement> Requirements => Table;

    private static readonly IReadOnlyDictionary<string, CapabilityRequirement> Table =
        new Dictionary<string, CapabilityRequirement>(StringComparer.Ordinal)
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
                "managed process module list, the kernel's mapped-file names, PE headers and WinVerifyTrust",
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
            ["put_file"] = new(
                "hash-verified file write over the server's own channel",
                null,
                "an unelevated server can only write where the current account already can"),
            ["get_file"] = new(
                "hash-verified sliced file read over the server's own channel",
                null,
                "an unelevated server can only read what the current account already can"),
            ["run_command"] = new(
                "arbitrary command execution on the host",
                null,
                "runs commands as the current account, so an unelevated server cannot touch anything " +
                "that account cannot"),
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
}
