using System.ComponentModel;
using System.Text;
using MacDiag.Mcp.Diagnostics.Services;
using ModelContextProtocol.Server;

namespace MacDiag.Mcp.Tools;

/// <summary>Structured result of <c>service_control</c>.</summary>
public sealed record ServiceControlToolResult(string Summary, ServiceControlResult Result);

/// <summary>Changing what runs on the Mac. Registered only on a writable server.</summary>
[McpServerToolType]
public sealed class ControlTools(IServiceController services)
{
    [McpServerTool(
        Name = "service_control",
        Title = "Start, stop or restart a launchd daemon",
        ReadOnly = false,
        Destructive = true,
        Idempotent = false,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Start, stop or restart a launchd system daemon and report its state before and after. start kickstarts a " +
        "loaded job or loads its plist from /Library/LaunchDaemons; stop unloads it (launchctl bootout), and it stays " +
        "unloaded until started again or the Mac restarts; restart kills and restarts it (kickstart -k). System " +
        "daemons only - not a user's LaunchAgents. Stopping or restarting Apple's own jobs (Remote Login among them), " +
        "remote-access and VPN agents, labels in MACDIAG_PROTECTED_LABELS, or this server's own job (use update_self) " +
        "is refused. A stop still in progress after 75 seconds is reported as still unloading.")]
    public async Task<ServiceControlToolResult> ServiceControl(
        [Description("The launchd label, for example 'com.example.daemon'. Check it with service_config first.")] string serviceName,
        [Description("'start', 'stop' or 'restart'")] string action,
        CancellationToken cancellationToken = default)
    {
        var result = await services.ControlAsync(serviceName, ParseServiceAction(action), cancellationToken).ConfigureAwait(false);
        return new ServiceControlToolResult(RenderService(result), result);
    }

    internal static ServiceAction ParseServiceAction(string action) => action?.Trim().ToLowerInvariant() switch
    {
        "start" => ServiceAction.Start,
        "stop" => ServiceAction.Stop,
        "restart" or "bounce" => ServiceAction.Restart,
        _ => throw new ArgumentException($"'{action}' is not an action. Use 'start', 'stop' or 'restart'.", nameof(action)),
    };

    internal static string RenderService(ServiceControlResult result) =>
        new StringBuilder()
            .Append(result.Action).Append(' ').Append(RenderLimits.Printable(result.Label)).AppendLine(":")
            .Append(RenderLimits.Printable(result.Detail))
            .ToString();
}
