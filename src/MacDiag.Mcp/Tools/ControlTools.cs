using System.ComponentModel;
using System.Text;
using MacDiag.Mcp.Diagnostics.Control;
using MacDiag.Mcp.Diagnostics.Services;
using ModelContextProtocol.Server;

namespace MacDiag.Mcp.Tools;

/// <summary>Structured result of <c>service_control</c>.</summary>
public sealed record ServiceControlToolResult(string Summary, ServiceControlResult Result);

/// <summary>Structured result of <c>process_control</c>.</summary>
public sealed record ProcessControlToolResult(string Summary, ProcessControlResult Result);

/// <summary>Changing what runs on the Mac. Registered only on a writable server.</summary>
[McpServerToolType]
public sealed class ControlTools(IServiceController services, IProcessController processes)
{
    [McpServerTool(
        Name = "process_control",
        Title = "Terminate, kill, suspend or resume a process",
        ReadOnly = false,
        Destructive = true,
        Idempotent = false,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Terminate, kill, suspend or resume a running process by signal. 'terminate' sends SIGTERM and waits up to " +
        "10 seconds to see it exit - unlike windiag, where terminate is a hard kill; 'kill' sends SIGKILL, which " +
        "cannot be caught. 'suspend' (SIGSTOP) freezes the process without ending it, so a hang can be caught in the " +
        "act; 'resume' (SIGCONT) undoes it. You must pass the name you expect alongside the PID; pass expectedStartTime " +
        "from process_list as well to catch a PID reused by a process with the same name. The name and start time are " +
        "checked, then checked again just before the signal; macOS has no pidfd, so a window of milliseconds remains, " +
        "and the result says so. PID 1 (launchd), the kernel, loginwindow, WindowServer, logd, opendirectoryd, sshd " +
        "and screen sharing, this server itself, zombies, and the main process of any launchd job service_control " +
        "protects are refused for everything but resume - including a user's own remote-access or VPN agent, found in " +
        "that user's launchd domain. Suspending a child of this server is refused: on macOS it would hang the server. " +
        "Apple's per-user agents (Finder, Dock) may be restarted: launchd relaunches them.")]
    public async Task<ProcessControlToolResult> ProcessControl(
        [Description("Process id to act on. Get a current one from process_list.")] int processId,
        [Description("The name you expect that PID to be, e.g. 'nginx' or '/usr/local/bin/nginx'. Verified before anything happens.")] string expectedName,
        [Description("'terminate', 'kill', 'suspend' or 'resume'")] string action = "suspend",
        [Description("The start time process_list reported for this PID. When given, a process started at any other time is refused.")] DateTimeOffset? expectedStartTime = null,
        CancellationToken cancellationToken = default)
    {
        var result = await processes.ControlAsync(processId, expectedName, ParseAction(action), expectedStartTime, cancellationToken).ConfigureAwait(false);
        return new ProcessControlToolResult(Render(result), result);
    }

    internal static ProcessAction ParseAction(string action) => action?.Trim().ToLowerInvariant() switch
    {
        "terminate" or "end" => ProcessAction.Terminate,
        "kill" => ProcessAction.Kill,
        "suspend" or "freeze" or "pause" => ProcessAction.Suspend,
        "resume" or "unfreeze" or "continue" => ProcessAction.Resume,
        _ => throw new ArgumentException($"'{action}' is not an action. Use 'terminate', 'kill', 'suspend' or 'resume'.", nameof(action)),
    };

    internal static string Render(ProcessControlResult result) =>
        new StringBuilder()
            .Append(result.Action).Append(' ').Append(RenderLimits.Printable(result.ProcessName)).Append(" (PID ").Append(result.ProcessId).AppendLine("):")
            .Append(RenderLimits.Printable(result.Detail))
            .ToString();

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
