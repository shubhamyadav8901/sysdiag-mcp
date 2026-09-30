using System.ComponentModel;
using System.Text;
using LinuxDiag.Mcp.Diagnostics.Control;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

/// <summary>Structured result of <c>process_control</c>.</summary>
public sealed record ProcessControlToolResult(string Summary, ProcessControlResult Result);

[McpServerToolType]
public sealed class ControlTools(IProcessController controller)
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
        "name you expect alongside the PID. It is checked through a pidfd, so a PID reused since your process_list " +
        "can never be signalled by mistake. PID 1, kernel threads and this server itself are refused.")]
    public ProcessControlToolResult ProcessControl(
        [Description("Process id to act on. Get a current one from process_list.")] int processId,
        [Description("The name you expect that PID to be, e.g. 'nginx' or '/usr/sbin/nginx'. Verified before anything happens.")] string expectedName,
        [Description("'terminate', 'kill', 'suspend' or 'resume'")] string action = "suspend",
        CancellationToken cancellationToken = default)
    {
        var result = controller.Control(processId, expectedName, ParseAction(action), cancellationToken);
        return new ProcessControlToolResult(Render(result), result);
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
        builder.Append(result.Action).Append(' ').Append(result.ProcessName).Append(" (PID ").Append(result.ProcessId).AppendLine("):");
        builder.AppendLine(result.Detail);
        if (result.Action == ProcessAction.Suspend)
        {
            builder.Append("Remember to resume it - a process left stopped is indistinguishable from one that is hung.");
        }

        return builder.ToString().TrimEnd();
    }
}
