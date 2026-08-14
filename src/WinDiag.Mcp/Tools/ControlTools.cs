using System.ComponentModel;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics.Control;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>process_control</c>.</summary>
public sealed record ProcessControlToolResult(string Summary, ProcessControlResult Result);

/// <summary>Structured result of <c>service_control</c>.</summary>
public sealed record ServiceControlToolResult(string Summary, ServiceControlResult Result);

/// <summary>Changing the machine's state. Registered only outside read-only mode.</summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class ControlTools
{
    private readonly IProcessController _processes;
    private readonly IServiceController _services;

    public ControlTools(IProcessController processes, IServiceController services)
    {
        _processes = processes;
        _services = services;
    }

    [McpServerTool(
        Name = "process_control",
        Title = "Terminate, suspend or resume a process",
        ReadOnly = false,
        Destructive = true,
        Idempotent = false,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Terminate, suspend or resume a running process. " +
        "Suspend is the interesting one for diagnosis: it freezes every thread without ending the " +
        "process, so a hang can be caught in the act and dumped. Terminate is irreversible and loses " +
        "anything the process had not written out. " +
        "You must pass the process name you expect alongside the PID, and it is verified first - PIDs " +
        "are reused, so one read from an earlier process_list may belong to something else entirely by " +
        "now. Core Windows processes are refused outright.")]
    public ProcessControlToolResult ProcessControl(
        [Description("Process id to act on. Get a current one from process_list.")]
        int processId,
        [Description("The image name you expect that PID to be, e.g. 'notepad' or 'notepad.exe'. Verified before anything happens.")]
        string expectedName,
        [Description("'terminate', 'suspend' or 'resume'")]
        string action = "suspend",
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedName);

        var result = _processes.Control(processId, expectedName, ParseProcessAction(action), cancellationToken);

        return new ProcessControlToolResult(RenderProcess(result), result);
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
        "Start, stop or restart a Windows service. Use it for the driver and agent restart loops that " +
        "make up most of the work when debugging a service that misbehaves. " +
        "Stopping a service also stops whatever depends on it, and those dependents are reported " +
        "because restarting the named service does NOT bring them back. Core Windows services are " +
        "refused - several of them would take these diagnostics down along with the machine.")]
    public ServiceControlToolResult ServiceControl(
        [Description("Service short name, e.g. 'Spooler'. Check it with service_config first.")]
        string serviceName,
        [Description("'start', 'stop' or 'restart'")]
        string action,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
        ArgumentException.ThrowIfNullOrWhiteSpace(action);

        var result = _services.Control(serviceName, ParseServiceAction(action), cancellationToken);

        return new ServiceControlToolResult(RenderService(result), result);
    }

    internal static ProcessAction ParseProcessAction(string action) =>
        action?.Trim().ToLowerInvariant() switch
        {
            "terminate" or "kill" or "end" => ProcessAction.Terminate,
            "suspend" or "freeze" or "pause" => ProcessAction.Suspend,
            "resume" or "unfreeze" or "continue" => ProcessAction.Resume,
            _ => throw new ArgumentException(
                $"'{action}' is not an action. Use 'terminate', 'suspend' or 'resume'.", nameof(action))
        };

    internal static ServiceAction ParseServiceAction(string action) =>
        action?.Trim().ToLowerInvariant() switch
        {
            "start" => ServiceAction.Start,
            "stop" => ServiceAction.Stop,
            "restart" or "bounce" => ServiceAction.Restart,
            _ => throw new ArgumentException(
                $"'{action}' is not an action. Use 'start', 'stop' or 'restart'.", nameof(action))
        };

    internal static string RenderProcess(ProcessControlResult result)
    {
        var builder = new StringBuilder();

        builder.Append(result.Action).Append(' ').Append(result.ProcessName)
            .Append(" (PID ").Append(result.ProcessId).AppendLine("):");
        builder.AppendLine(result.Detail);

        if (result.Action == ProcessAction.Suspend)
        {
            // A forgotten suspended process looks exactly like a hung one, which is a confusing thing
            // to leave behind on a machine somebody else will look at next.
            builder.Append("Remember to resume it - a process left suspended is indistinguishable from " +
                           "one that is hung.");
        }

        return builder.ToString().TrimEnd();
    }

    internal static string RenderService(ServiceControlResult result)
    {
        var builder = new StringBuilder();

        builder.Append(result.ServiceName);
        if (result.DisplayName is { } display && !string.Equals(display, result.ServiceName, StringComparison.Ordinal))
        {
            builder.Append(" (").Append(display).Append(')');
        }

        builder.AppendLine();
        builder.AppendLine(result.Detail);

        if (result.DependentServicesStopped.Count > 0)
        {
            builder.AppendLine().AppendLine("Dependent services stopped:");
            foreach (var dependent in result.DependentServicesStopped)
            {
                builder.Append("- ").AppendLine(dependent);
            }

            builder.Append("Start these again individually if they are needed.");
        }

        return builder.ToString().TrimEnd();
    }
}
