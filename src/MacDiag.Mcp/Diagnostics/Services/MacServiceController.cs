using System.Diagnostics;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Mac.Launchd;
using MacDiag.Mcp.Mac.Parsers;
using Microsoft.Extensions.Logging;

namespace MacDiag.Mcp.Diagnostics.Services;

/// <summary>Starts, stops and restarts a system launchd daemon.</summary>
/// <remarks>
/// <para>start: kickstart a loaded job, or bootstrap its plist; stop: bootout, which unloads it until it is started
/// again or the Mac restarts; restart: kickstart -k. The system domain only -- a root daemon reaching into a user's
/// GUI session is rarely what the caller means.</para>
/// <para>bootout returns before the job is gone (and may exit 36, "Operation now in progress"), so the stop waits
/// until launchd has let it go, up to the job wait, and reports "still unloading" rather than an error after that.</para>
/// </remarks>
public sealed class MacServiceController(IExternalCommand commands, MacDiagOptions options, ILogger<MacServiceController> logger) : IServiceController
{
    private const int OperationInProgress = 36;
    private readonly LaunchdProtection _protection = new(options);

    internal LaunchdPlists Plists { get; init; } = new();

    internal TimeSpan PollDelay { get; init; } = TimeSpan.FromSeconds(1);

    internal TimeSpan JobWait { get; init; } = TimeSpan.FromSeconds(75);

    public async Task<ServiceControlResult> ControlAsync(string label, ServiceAction action, CancellationToken cancellationToken)
    {
        LaunchdLabel.Check(label, nameof(label));
        if (action != ServiceAction.Start && _protection.Refusal(label) is { } refusal)
        {
            throw new ServiceControlException(refusal);
        }

        var target = $"system/{label}";
        var before = await StateAsync(target, cancellationToken).ConfigureAwait(false);
        string verb;
        switch (action)
        {
            case ServiceAction.Start when before is not null:
                verb = "kickstart";
                await RunAsync(["kickstart", target], label, cancellationToken).ConfigureAwait(false);
                break;

            case ServiceAction.Start:
                verb = "bootstrap";
                await RunAsync(["bootstrap", "system", await PlistToStartAsync(label, cancellationToken).ConfigureAwait(false)], label, cancellationToken)
                    .ConfigureAwait(false);
                break;

            case ServiceAction.Stop when before is null:
                return new ServiceControlResult(label, action, "not loaded", "not loaded", $"'{label}' was not loaded; nothing to stop.");

            case ServiceAction.Stop:
                verb = "bootout";
                var bootout = await commands.RunAsync("launchctl", ["bootout", target], JobWait, cancellationToken).ConfigureAwait(false);
                if (bootout.ExitCode is not (0 or OperationInProgress))
                {
                    throw Failed("bootout", label, bootout);
                }

                break;

            case ServiceAction.Restart when before is null:
                throw new ServiceControlException($"'{label}' is not loaded, so there is nothing to restart; use start. Nothing has been done.");

            default:
                verb = "kickstart -k";
                await RunAsync(["kickstart", "-k", target], label, cancellationToken).ConfigureAwait(false);
                break;
        }

        logger.LogWarning("service_control: {Action} {Label}", action, label);

        var after = action == ServiceAction.Stop
            ? await WaitUnloadedAsync(target, cancellationToken).ConfigureAwait(false)
            : Describe(await StateAsync(target, cancellationToken).ConfigureAwait(false));
        var detail = $"{verb}: {Describe(before)} -> {after}.";
        if (action != ServiceAction.Stop && after.StartsWith("not running", StringComparison.Ordinal))
        {
            detail += $" It is not running now; check event_log_tail for its process, or service_config for its last exit.";
        }

        if (action == ServiceAction.Stop)
        {
            detail += " It stays unloaded until it is started again or the Mac restarts.";
        }

        return new ServiceControlResult(label, action, Describe(before), after, detail);
    }

    /// <summary>The daemon plist that defines exactly this label, refusing a disabled job or a plist for another label.</summary>
    private async Task<string> PlistToStartAsync(string label, CancellationToken cancellationToken)
    {
        var disabled = await commands.RunAsync("launchctl", ["print-disabled", "system"], JobWait, cancellationToken).ConfigureAwait(false);
        if (disabled.ExitCode == 0 && LaunchctlDisabled.Parse(disabled.StandardOutput).TryGetValue(label, out var off) && off)
        {
            throw new ServiceControlException(
                $"launchd has '{label}' disabled, so it cannot be started; enable it with launchctl enable system/{label} first. Nothing has been done.");
        }

        var plist = await Plists.FindAsync(commands, label, LaunchdPlists.DaemonDirectories, cancellationToken).ConfigureAwait(false)
                    ?? throw new ServiceControlException(
                        $"No daemon plist for '{label}' in {string.Join(" or ", LaunchdPlists.DaemonDirectories)}, so there is nothing to start. Nothing has been done.");

        var declared = await Plutil.LabelAsync(commands, plist, JobWait, cancellationToken).ConfigureAwait(false);
        return declared == label
            ? plist
            : throw new ServiceControlException(
                $"{plist} declares the label '{declared ?? "(none)"}', not '{label}'; starting it would load another job. Nothing has been done.");
    }

    private async Task RunAsync(string[] arguments, string label, CancellationToken cancellationToken)
    {
        var result = await commands.RunAsync("launchctl", arguments, JobWait, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            throw Failed(arguments[0], label, result);
        }
    }

    private async Task<string> WaitUnloadedAsync(string target, CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        do
        {
            if (await StateAsync(target, cancellationToken).ConfigureAwait(false) is null)
            {
                return "not loaded";
            }

            await Task.Delay(PollDelay, cancellationToken).ConfigureAwait(false);
        }
        while (watch.Elapsed < JobWait);

        return await StateAsync(target, cancellationToken).ConfigureAwait(false) is null ? "not loaded" : "still unloading";
    }

    private async Task<LaunchdJobState?> StateAsync(string target, CancellationToken cancellationToken)
    {
        var result = await commands.RunAsync("launchctl", ["print", target], JobWait, cancellationToken).ConfigureAwait(false);
        return result.ExitCode == 0 ? LaunchctlPrint.State(result.StandardOutput) : null;
    }

    private static string Describe(LaunchdJobState? state) =>
        state is null ? "not loaded"
        : state.ProcessId is { } pid ? $"{state.State ?? "loaded"} (PID {pid})"
        : state.State ?? "loaded";

    private static ServiceControlException Failed(string verb, string label, ExternalResult result) =>
        new($"Could not {verb} '{label}': launchctl reported (exit {result.ExitCode}): {(result.StandardError + result.StandardOutput).Trim()}. Nothing more was done.");
}
