using System.ComponentModel;
using System.Globalization;
using System.Text;
using LinuxDiag.Mcp.Diagnostics.Services;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

/// <summary>Structured result of <c>service_config</c>.</summary>
public sealed record ServiceConfigResult(string Summary, string Query, ServiceInfo? Service, IReadOnlyList<string> Candidates);

[McpServerToolType]
public sealed class ServiceTools(IServiceInspector services)
{
    [McpServerTool(
        Name = "service_config",
        Title = "Service configuration and state",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Show a systemd service's state and configuration: whether it is enabled to start at boot and what it is " +
        "doing now, its last result and restart count, the account it runs as, its command line, its main PID, the " +
        "unit file and any drop-ins that change it, and its dependencies in both directions. Accepts 'cron' or " +
        "'cron.service'. Use it for 'the service did not start', 'it keeps restarting', 'it runs as the wrong " +
        "account', or to work out what else stops if this one is stopped. If the name does not match, near " +
        "matches by name or description are suggested.")]
    public async Task<ServiceConfigResult> ServiceConfig(
        [Description("Service name, for example 'cron' or 'ssh.service'")] string name,
        CancellationToken cancellationToken = default)
    {
        var result = await services.QueryAsync(name, cancellationToken).ConfigureAwait(false);
        return new ServiceConfigResult(Render(result), result.Query, result.Service, result.Candidates);
    }

    internal static string Render(ServiceQueryResult result)
    {
        var text = new StringBuilder();
        if (result.Service is not { } service)
        {
            text.Append("No service named '").Append(RenderLimits.Printable(result.Query)).Append("' exists.");
            if (result.Candidates.Count > 0)
            {
                text.AppendLine(" Did you mean one of these?");
                foreach (var candidate in result.Candidates)
                {
                    text.Append("- ").AppendLine(RenderLimits.Printable(candidate));
                }
            }

            return text.ToString().TrimEnd();
        }

        text.Append(RenderLimits.Printable(service.ServiceName));
        if (service.DisplayName is { } display)
        {
            text.Append(" (").Append(RenderLimits.Printable(display)).Append(')');
        }

        text.Append(" - ").Append(RenderLimits.Printable(service.Status)).Append(", start type ").AppendLine(RenderLimits.Printable(service.StartType));
        if (service.StartType == "masked" || service.LoadState == "masked")
        {
            text.AppendLine("NOTE: this service is MASKED and cannot be started until it is unmasked.");
        }
        else if (service.StartType.StartsWith("enabled", StringComparison.Ordinal) &&
                 (service.Status.StartsWith("inactive", StringComparison.Ordinal) || service.Status.StartsWith("failed", StringComparison.Ordinal)))
        {
            text.Append("NOTE: enabled to start at boot but is currently ").Append(RenderLimits.Printable(service.Status.Split(' ')[0]))
                .Append(" - check event_log_tail with unit='").Append(RenderLimits.Printable(service.ServiceName)).AppendLine("' for why.");
        }

        if (service.Result is { } resultText && resultText != "success")
        {
            text.Append("Last result: ").AppendLine(RenderLimits.Printable(resultText));
        }

        if (service.RestartCount > 0)
        {
            text.Append("Restarted ").Append(service.RestartCount).Append(" times by systemd (Restart=")
                .Append(RenderLimits.Printable(service.Restart)).AppendLine(").");
        }

        text.Append("Runs as: ").AppendLine(RenderLimits.Printable(service.Account));
        text.Append("Type: ").AppendLine(RenderLimits.Printable(service.ServiceType));
        text.Append("Command: ").AppendLine(RenderLimits.Printable(service.ImagePath ?? "(none)"));
        if (service.MainProcessId is { } pid)
        {
            text.Append("Main PID: ").Append(pid).AppendLine();
        }

        text.Append("Unit file: ").AppendLine(RenderLimits.Printable(service.FragmentPath ?? "(none)"));
        if (service.DropIns.Count > 0)
        {
            text.Append("Drop-ins: ").AppendLine(RenderLimits.Printable(string.Join(", ", service.DropIns)));
        }

        if (service.ActiveSince is { } since)
        {
            text.Append("Active since: ").AppendLine(since.ToString("u", CultureInfo.InvariantCulture));
        }

        if (service.LastExitStatus is { } exit && !service.Status.StartsWith("active", StringComparison.Ordinal))
        {
            text.Append("Last exit status: ").Append(exit).AppendLine();
        }

        text.Append("Depends on: ").AppendLine(RenderLimits.Printable(service.DependsOn.Count == 0 ? "(none)" : string.Join(", ", service.DependsOn)));
        if (service.WeakDependsOn.Count > 0)
        {
            text.Append("Wants (runs without them): ").AppendLine(RenderLimits.Printable(string.Join(", ", service.WeakDependsOn)));
        }

        text.Append("Stops with it: ").AppendLine(RenderLimits.Printable(service.DependedOnBy.Count == 0 ? "(none)" : string.Join(", ", service.DependedOnBy)));
        text.Append("Wanted by (keep running if it stops): ").Append(RenderLimits.Printable(service.WantedBy.Count == 0 ? "(none)" : string.Join(", ", service.WantedBy)));
        return text.ToString();
    }
}
