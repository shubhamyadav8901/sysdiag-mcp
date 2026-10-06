namespace WinDiag.Mcp.Diagnostics;

/// <summary>
/// What the write tools refuse to touch, in one place, so service_control, process_control and capture_dump
/// cannot drift apart.
/// </summary>
/// <remarks>
/// <para>Hardcoded on purpose: a configurable safety list is one that eventually gets configured empty.</para>
/// <para>They were three private lists in three classes, and drift is exactly what happened: service_control
/// refused to stop RpcSs, while process_control would terminate the svchost hosting it, and capture_dump would
/// write a full dump of lsass that get_file then read back with no grant at all.</para>
/// </remarks>
internal static class ProtectedTargets
{
    /// <summary>
    /// Services that must never be stopped or restarted, and whose host process must never be ended or frozen.
    /// </summary>
    /// <remarks>
    /// Stopping any of these takes the machine out of service, and several take the diagnostics with them --
    /// stop <c>Winmgmt</c> and <c>process_list</c> stops working; stop <c>RpcSs</c> and essentially everything
    /// does. <c>DcomLaunch</c>'s host is a critical process: ending it bugchecks the machine.
    /// </remarks>
    public static readonly IReadOnlySet<string> CriticalServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "RpcSs", "DcomLaunch", "RpcEptMapper", "LSM", "Power", "PlugPlay",
        "EventLog", "Winmgmt", "BFE", "mpssvc", "SamSs", "CryptSvc", "ProfSvc"
    };

    /// <summary>Image names of processes that hold the machine's credentials, which capture_dump refuses.</summary>
    /// <remarks>
    /// <para>A full dump of <c>lsass</c> is the standard way to lift NTLM hashes and Kerberos tickets off a host,
    /// and capture_dump writes into the artifact directory, which get_file reads without the arbitrary-read
    /// grant. So without this, a token with no grants at all could copy the machine's credentials off it, over
    /// a channel that is not encrypted. <c>lsaiso</c> is the Credential Guard half of the same thing.</para>
    /// <para><c>csrss</c> is refused with them because it is a protected process: the dump fails anyway on a
    /// default machine, and a named refusal says why, where the failure only said "access denied".</para>
    /// </remarks>
    public static readonly IReadOnlySet<string> CredentialProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "lsass", "lsaiso", "csrss"
    };

    /// <summary>Image names of processes that must never be ended or frozen, whatever the caller asks.</summary>
    /// <remarks>
    /// Ending any of these either bugchecks the machine or logs the session out. A diagnostics tool taking down
    /// the machine it is diagnosing is the single worst thing it can do, and "the caller asked for it" is no
    /// defence when the caller is a language model working from a stale PID. The credential processes are
    /// among them, so the two lists cannot disagree about lsass.
    /// </remarks>
    public static readonly IReadOnlySet<string> CoreProcesses = new HashSet<string>(
        ["System", "Idle", "Registry", "Memory Compression", "smss", "wininit", "winlogon", "services",
         .. CredentialProcesses],
        StringComparer.OrdinalIgnoreCase);
}
