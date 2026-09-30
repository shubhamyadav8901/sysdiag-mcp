using System.ComponentModel;
using System.Text;
using LinuxDiag.Mcp.Diagnostics.Control;
using LinuxDiag.Mcp.Diagnostics.Services;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

/// <summary>Structured result of <c>process_control</c>.</summary>
public sealed record ProcessControlToolResult(string Summary, ProcessControlResult Result);

/// <summary>Structured result of <c>service_control</c>.</summary>
public sealed record ServiceControlToolResult(string Summary, ServiceControlResult Result);

[McpServerToolType]
public sealed class ControlTools(IProcessController controller, IServiceController services)
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
        "cannot be caught, and matches windiag's terminate. 'suspend' (SIGSTOP) freezes every thread without " +
        "ending the process, so a hang can be caught in the act; 'resume' (SIGCONT) undoes it. You must pass the " +
        "name you expect alongside the PID. It is checked through a pidfd, so the PID cannot change hands between " +
        "the check and the signal; pass expectedStartTime from process_list as well to also catch a PID reused, " +
        "before this call, by a process with the same name. PID 1, kernel threads, zombies and this server itself " +
        "are refused.")]
    public ProcessControlToolResult ProcessControl(
        [Description("Process id to act on. Get a current one from process_list.")] int processId,
        [Description("The name you expect that PID to be, e.g. 'nginx' or '/usr/sbin/nginx'. Verified before anything happens.")] string expectedName,
        [Description("'terminate', 'kill', 'suspend' or 'resume'")] string action = "suspend",
        [Description("The start time process_list reported for this PID. When given, a process started at any other time is refused.")] DateTimeOffset? expectedStartTime = null,
        CancellationToken cancellationToken = default)
    {
        var result = controller.Control(processId, expectedName, ParseAction(action), cancellationToken, expectedStartTime);
        return new ProcessControlToolResult(Render(result), result);
    }

    [McpServerTool(
        Name = "service_control",
        Title = "Start, stop or restart a service",
        ReadOnly = false,
        Destructive = true,
        Idempotent = false,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Start, stop or restart a systemd service and report its state before and after. Stopping a service also " +
        "stops whatever depends on it, and those dependents are reported, because restarting the named service does " +
        "NOT bring them back. Services only - no targets, sockets or patterns. Stopping or restarting a service that " +
        "would cut the machine off (journald, logind, udevd, networking, name resolution, dbus, polkit, ssh), this " +
        "server's own service, or anything it depends on, is refused. A job still running after 75 seconds is " +
        "reported as still running; systemd finishes it.")]
    public async Task<ServiceControlToolResult> ServiceControl(
        [Description("Service name, for example 'nginx' or 'nginx.service'. Check it with service_config first.")] string serviceName,
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

    internal static string RenderService(ServiceControlResult result)
    {
        var builder = new StringBuilder(RenderLimits.Printable(result.ServiceName));
        if (result.DisplayName is { } display)
        {
            builder.Append(" (").Append(RenderLimits.Printable(display)).Append(')');
        }

        builder.AppendLine().AppendLine(RenderLimits.Printable(result.Detail));
        if (result.DependentServicesStopped.Count > 0)
        {
            builder.AppendLine().AppendLine("Dependent services stopped:");
            foreach (var dependent in result.DependentServicesStopped)
            {
                builder.Append("- ").AppendLine(RenderLimits.Printable(dependent));
            }

            builder.Append("Start these again individually if they are needed.");
        }

        return builder.ToString().TrimEnd();
    }

    internal static ProcessAction ParseAction(string action) => action?.Trim().ToLowerInvariant() switch
    {
        "terminate" or "end" => ProcessAction.Terminate,
        "kill" => ProcessAction.Kill,
        "suspend" or "freeze" or "pause" => ProcessAction.Suspend,
        "resume" or "unfreeze" or "continue" => ProcessAction.Resume,
        _ => throw new ArgumentException(
            $"'{action}' is not an action. Use 'terminate', 'kill', 'suspend' or 'resume'.", nameof(action)),
    };

    internal static string Render(ProcessControlResult result)
    {
        var builder = new StringBuilder();
        builder.Append(result.Action).Append(' ').Append(RenderLimits.Printable(result.ProcessName)).Append(" (PID ").Append(result.ProcessId).AppendLine("):");
        builder.AppendLine(RenderLimits.Printable(result.Detail));
        if (result.Action == ProcessAction.Suspend)
        {
            builder.Append("Remember to resume it - a process left stopped is indistinguishable from one that is hung.");
        }

        return builder.ToString().TrimEnd();
    }
}
