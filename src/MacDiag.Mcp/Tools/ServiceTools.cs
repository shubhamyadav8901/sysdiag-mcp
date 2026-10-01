using System.ComponentModel;
using System.Globalization;
using System.Text;
using MacDiag.Mcp.Diagnostics.Services;
using ModelContextProtocol.Server;

namespace MacDiag.Mcp.Tools;

/// <summary>Structured result of <c>service_config</c>.</summary>
public sealed record ServiceConfigResult(string Summary, string Query, ServiceInfo? Service, IReadOnlyList<string> Candidates);

[McpServerToolType]
public sealed class ServiceTools(IServiceInspector services)
{
    [McpServerTool(
        Name = "service_config",
        Title = "launchd job configuration and state",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Show a launchd job's state and configuration: whether it is loaded and running, its PID, last exit status " +
        "and run count, the program and arguments it runs, whether it starts at load and how KeepAlive restarts it, " +
        "the account it runs as, the plist it comes from, and whether launchd has it disabled. Takes the job's label, " +
        "for example 'com.openssh.sshd' (Remote Login). Use it for 'the daemon did not start', 'it keeps restarting', " +
        "or 'what does this job run'. If the label does not match, near matches are suggested. Configuration is read " +
        "from the plist; launchctl's own output is used only for runtime state, because Apple documents it as unstable.")]
    public async Task<ServiceConfigResult> ServiceConfig(
        [Description("The launchd label, for example 'com.openssh.sshd' or 'com.example.daemon'")] string name,
        CancellationToken cancellationToken = default)
    {
        var result = await services.QueryAsync(name, cancellationToken).ConfigureAwait(false);
        return new ServiceConfigResult(Render(result), result.Query, result.Service, result.Candidates);
    }

    internal static string Render(ServiceQueryResult result)
    {
        var builder = new StringBuilder();
        if (result.Service is not { } service)
        {
            builder.Append("No launchd job labelled '").Append(RenderLimits.Printable(result.Query)).Append("' was found.");
            if (result.Candidates.Count > 0)
            {
                builder.AppendLine().Append("Did you mean: ").Append(RenderLimits.Join(result.Candidates.Select(c => RenderLimits.Printable(c)).ToList()));
            }

            return builder.ToString();
        }

        builder.Append(RenderLimits.Printable(service.Label)).Append(" (").Append(RenderLimits.Printable(service.Domain)).Append("): ")
            .Append(RenderLimits.Printable(service.Status));
        if (service.MainProcessId is { } pid)
        {
            builder.Append(", PID ").Append(pid);
        }

        builder.AppendLine();
        if (service.PlistPath is { } plist)
        {
            builder.Append("Plist: ").AppendLine(RenderLimits.Printable(plist));
        }

        if (service.Program is { } program)
        {
            builder.Append("Runs: ").Append(RenderLimits.Printable(program));
            if (service.Arguments.Count > 1)
            {
                builder.Append(' ').Append(RenderLimits.Printable(string.Join(' ', service.Arguments.Skip(1))));
            }

            builder.AppendLine();
        }

        builder.Append("As ").Append(RenderLimits.Printable(service.Account ?? "?"))
            .Append(service.RunAtLoad ? "; starts at load" : "; not started at load");
        if (service.KeepAlive is { } keepAlive)
        {
            builder.Append("; KeepAlive ").Append(RenderLimits.Printable(keepAlive));
        }

        builder.AppendLine();
        if (service.LastExitText is { } lastExit)
        {
            builder.Append("Last exit: ").Append(RenderLimits.Printable(lastExit));
            if (service.Runs is { } runs)
            {
                builder.Append(", ").Append(runs.ToString(CultureInfo.InvariantCulture)).Append(runs == 1 ? " run" : " runs");
            }

            builder.AppendLine();
        }

        if (service.Disabled == true)
        {
            builder.AppendLine("NOTE: launchd has this job disabled; it will not start until enabled.");
        }

        foreach (var limitation in service.Limitations)
        {
            builder.Append("WARNING: ").AppendLine(RenderLimits.Printable(limitation));
        }

        return builder.ToString().TrimEnd();
    }
}
