using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Hosting;

namespace MacDiag.Mcp.Mac.Launchd;

/// <summary>Which launchd jobs the control tools refuse to stop or restart -- and whose main process they refuse to signal.</summary>
/// <remarks>
/// <para>One rule for service_control and process_control, so the two cannot drift: a job protected from bootout is
/// protected from a kill of its process too.</para>
/// <para>Matched case-insensitively although launchd is case-sensitive: a case variant can only refuse more, never less.</para>
/// </remarks>
public sealed class LaunchdProtection(MacDiagOptions options)
{
    private const string ApplePrefix = "com.apple.";

    /// <summary>Apple's own jobs (Remote Login among them), and the remote-access and VPN agents a Mac may be reached through.</summary>
    internal static readonly string[] Prefixes =
    [
        ApplePrefix, "com.openssh.", "com.tailscale.", "io.tailscale.", "com.wireguard.", "net.openvpn.", "org.openvpn.",
        "com.zerotier.", "com.cisco.anyconnect", "com.cisco.secureclient", "com.paloaltonetworks.gp", "com.fortinet.",
        "com.teamviewer.", "com.jamf.",
    ];

    /// <summary>Why the job may not be stopped or restarted, ending "Nothing has been done."; null when it may.</summary>
    public string? Refusal(string label)
    {
        ArgumentNullException.ThrowIfNull(label);

        if (Same(label, options.ServiceLabel) || Same(label, MacServiceInstallOptions.DefaultLabel))
        {
            return $"'{label}' is this server's own job; use update_self to restart it. Nothing has been done.";
        }

        if (Prefixes.FirstOrDefault(p => label.StartsWith(p, StringComparison.OrdinalIgnoreCase)) is { } prefix)
        {
            return $"'{label}' is protected ({prefix}*): stopping it could cut this Mac off or take down part of the system. Nothing has been done.";
        }

        return Configured(label);
    }

    /// <summary>The rule for a job in a user's own launchd domain: everything <see cref="Refusal"/> protects but Apple's agents.</summary>
    /// <remarks>
    /// Apple's per-user agents -- Finder, Dock, SystemUIServer -- are relaunched by launchd, and restarting one is
    /// ordinary troubleshooting; the ones a Mac is reached through (screen sharing, ARDAgent) are refused by name
    /// before any list is read. A user's remote-access and VPN agents, the configured labels and this server's own job
    /// stay protected.
    /// </remarks>
    public string? RefusalInUserDomain(string label)
    {
        ArgumentNullException.ThrowIfNull(label);

        if (!label.StartsWith(ApplePrefix, StringComparison.OrdinalIgnoreCase) || Same(label, options.ServiceLabel))
        {
            return Refusal(label);
        }

        return Configured(label);
    }

    private string? Configured(string label) =>
        options.ProtectedLabels.FirstOrDefault(p => Matches(label, p)) is { } configured
            ? $"'{label}' is protected by MACDIAG_PROTECTED_LABELS ({configured}). Nothing has been done."
            : null;

    /// <summary>An entry ending in "." protects every label it begins; any other entry is one exact label.</summary>
    private static bool Matches(string label, string entry) =>
        entry.EndsWith('.') ? label.StartsWith(entry, StringComparison.OrdinalIgnoreCase) : Same(label, entry);

    private static bool Same(string label, string? other) => string.Equals(label, other, StringComparison.OrdinalIgnoreCase);
}
