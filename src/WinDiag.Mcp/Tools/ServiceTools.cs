using System.ComponentModel;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics.Services;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>service_config</c>.</summary>
public sealed record ServiceConfigResult(
    string Summary,
    string Query,
    ServiceInfo? Service,
    IReadOnlyList<string> Candidates);

/// <summary>Windows service inspection.</summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class ServiceTools
{
    private readonly IServiceInspector _services;

    public ServiceTools(IServiceInspector services)
    {
        _services = services;
    }

    [McpServerTool(
        Name = "service_config",
        Title = "Service configuration and state",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Show a Windows service's configured start type and its actual running state, plus the account " +
        "it runs as, its binary path, its description, and its dependencies in both directions. " +
        "Accepts either the short service name or the display name. Use it for 'the service did not " +
        "start', 'it starts too late', 'it runs as the wrong account', or to work out what else breaks " +
        "if this one is stopped. If the name does not match exactly, near matches are suggested.")]
    public ServiceConfigResult ServiceConfig(
        [Description("Service short name (for example 'Spooler') or display name (for example 'Print Spooler')")]
        string name,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var result = _services.Query(name, cancellationToken);
        return new ServiceConfigResult(Render(result), result.Query, result.Service, result.Candidates);
    }

    internal static string Render(ServiceQueryResult result)
    {
        if (result.Service is not { } service)
        {
            var builder = new StringBuilder();
            builder.Append("No service named '").Append(result.Query).Append("' exists.");

            if (result.Candidates.Count > 0)
            {
                builder.AppendLine(" Did you mean one of these?");
                foreach (var candidate in result.Candidates)
                {
                    builder.Append("- ").AppendLine(candidate);
                }
            }

            return builder.ToString().TrimEnd();
        }

        var text = new StringBuilder();

        text.Append(service.ServiceName);
        if (service.DisplayName is { } display && !string.Equals(display, service.ServiceName, StringComparison.Ordinal))
        {
            text.Append(" (").Append(display).Append(')');
        }

        text.Append(" - ").Append(service.Status).Append(", start type ").Append(service.StartType);
        if (service.DelayedAutoStart)
        {
            text.Append(" (delayed)");
        }

        text.AppendLine();

        // Configured-versus-actual is the single most useful contradiction this tool can surface, so
        // it is called out rather than left for the reader to spot across two fields.
        if (service.StartType is "Automatic" && service.Status is "Stopped")
        {
            text.AppendLine("NOTE: configured to start automatically but is currently stopped - check the " +
                            "System event log around boot time for why it failed or was stopped.");
        }
        else if (service.StartType is "Disabled")
        {
            text.AppendLine("NOTE: this service is DISABLED and cannot be started until its start type changes.");
        }

        text.Append("Runs as: ").AppendLine(service.Account ?? "(not recorded)");
        text.Append("Type: ").AppendLine(service.ServiceType);
        text.Append("Image: ").AppendLine(service.ImagePath ?? "(not recorded)");

        if (service.Description is { } description)
        {
            text.Append("Description: ").AppendLine(description);
        }

        AppendList(text, "Depends on", service.DependsOn);
        AppendList(text, "Depended on by", service.DependedOnBy);

        return text.ToString().TrimEnd();
    }

    private static void AppendList(StringBuilder builder, string label, IReadOnlyList<string> values)
    {
        builder.Append(label).Append(": ")
            .AppendLine(values.Count == 0 ? "(none)" : string.Join(", ", values));
    }
}
