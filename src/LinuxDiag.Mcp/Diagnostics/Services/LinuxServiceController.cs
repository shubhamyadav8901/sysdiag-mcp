using LinuxDiag.Mcp.Linux.External;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Linux.Proc;
using Microsoft.Extensions.Logging;

namespace LinuxDiag.Mcp.Diagnostics.Services;

public sealed partial class LinuxServiceController(IExternalCommand commands, ILogger<LinuxServiceController> logger)
    : IServiceController
{
    /// <summary>How long a start, stop or restart job is waited for.</summary>
    /// <remarks>
    /// Under the relay's HTTP client timeout, so a slow job is reported as still running rather than as a
    /// dropped call. Killing systemctl does not cancel the job; systemd finishes it either way.
    /// </remarks>
    internal static readonly TimeSpan JobWait = TimeSpan.FromSeconds(75);

    private static readonly TimeSpan QueryWait = TimeSpan.FromSeconds(30);

    /// <summary>Services whose stop cuts this machine off -- logging, logins, devices, networking, remote access.</summary>
    /// <remarks>Matched against every name a unit answers to, so an alias (sshd for ssh) cannot slip past.</remarks>
    internal static readonly HashSet<string> Critical = new(StringComparer.Ordinal)
    {
        "dbus.service", "dbus-broker.service", "systemd-journald.service", "systemd-logind.service",
        "systemd-udevd.service", "systemd-networkd.service", "NetworkManager.service", "systemd-resolved.service",
        "ssh.service", "sshd.service", "polkit.service", "networking.service", "tailscaled.service", "openvpn.service",
        "zerotier-one.service", "strongswan.service",
    };

    /// <summary>Templates whose every instance is a tunnel the machine may be reached through.</summary>
    private static readonly string[] CriticalTemplates = ["wg-quick@", "openvpn@", "openvpn-client@", "openvpn-server@"];

    internal static bool IsCritical(string unit) =>
        Critical.Contains(unit) || CriticalTemplates.Any(t => unit.StartsWith(t, StringComparison.Ordinal));

    /// <summary>Targets a unit pulls in only if running it shuts down, reboots or suspends the machine.</summary>
    private static readonly HashSet<string> ShutdownTargets = new(StringComparer.Ordinal)
    {
        "shutdown.target", "final.target", "umount.target", "sleep.target",
    };

    /// <summary>This server's own unit, from its cgroup: the name is configurable, so it is read, not assumed.</summary>
    internal Func<string?> SelfUnit { get; init; } = ReadSelfUnit;

    public async Task<ServiceControlResult> ControlAsync(string serviceName, ServiceAction action, CancellationToken cancellationToken)
    {
        var unit = ServiceNames.Normalise(serviceName, nameof(serviceName));
        var verb = action.ToString().ToLowerInvariant();
        var before = await ShowAsync([unit], cancellationToken).ConfigureAwait(false);
        var target = before.FirstOrDefault(u => u["Id"] == unit) ?? before.FirstOrDefault();
        if (target is null || target["LoadState"] == "not-found")
        {
            throw new ServiceControlException(
                $"No service named '{unit}' exists. Call service_config for near matches. Nothing has been done.");
        }

        // systemd-poweroff, -reboot, -halt, -kexec, -suspend and -hibernate are services too: starting one takes
        // the machine down. They are known by what they do, not by name, so a renamed copy is caught as well.
        if (target["SuccessAction"] is { Length: > 0 } and not "none" || target["FailureAction"] is { Length: > 0 } and not "none" ||
            target.List("Requires").FirstOrDefault(ShutdownTargets.Contains) is not null)
        {
            throw new ServiceControlException(
                $"Refusing to {verb} '{unit}': running it shuts down, reboots or suspends this machine " +
                $"(SuccessAction={target["SuccessAction"]}, FailureAction={target["FailureAction"]}, Requires={target["Requires"]}). Nothing has been done.");
        }

        var names = new[] { target["Id"] ?? unit }.Concat(target.List("Names")).ToHashSet(StringComparer.Ordinal);
        var self = SelfUnit();
        var dependents = new List<string>();
        if (action != ServiceAction.Start)
        {
            if (self is not null && names.Contains(self))
            {
                throw new ServiceControlException(
                    $"Refusing to {verb} '{unit}': it is this diagnostics server's own service. Use update_self to " +
                    "restart it with a new build. Nothing has been done.");
            }

            if (names.FirstOrDefault(IsCritical) is { } critical)
            {
                throw new ServiceControlException(
                    $"Refusing to {verb} '{unit}' ({critical}): stopping it cuts this machine off - logging, logins, " +
                    "devices, name resolution or remote access - and can take these diagnostics down with it. Nothing has been done.");
            }

            dependents = await ActiveDependentsAsync(unit, verb, cancellationToken).ConfigureAwait(false);
            if (self is not null && dependents.Contains(self))
            {
                throw new ServiceControlException(
                    $"Refusing to {verb} '{unit}': stopping it would also stop this diagnostics server, which depends " +
                    "on it. Nothing has been done.");
            }

            // A dependent is stopped with it, so a critical one is refused as if it had been named.
            if (dependents.FirstOrDefault(IsCritical) is { } criticalDependent)
            {
                throw new ServiceControlException(
                    $"Refusing to {verb} '{unit}': it would also stop {criticalDependent}, which depends on it, and that cuts " +
                    "this machine off. Nothing has been done.");
            }
        }

        string? stillRunning = null;
        try
        {
            var result = await commands.RunAsync("systemctl", ["--no-ask-password", verb, "--", unit], JobWait, cancellationToken)
                .ConfigureAwait(false);
            if (result.ExitCode != 0)
            {
                throw new ServiceControlException(
                    $"Could not {verb} '{unit}': systemctl reported: {LinuxServiceInspector.FirstLine(result.StandardError)}");
            }
        }
        catch (ExternalCommandException ex) when (ex.TimedOut)
        {
            stillRunning = $" The job did not finish within {JobWait.TotalSeconds:0} s; systemd keeps running it - call " +
                           "service_config to see where it got to.";
        }

        LogChanged(logger, verb, unit);
        var after = await ShowAsync([unit, .. dependents], cancellationToken).ConfigureAwait(false);
        // By the unit's own Id: systemctl answers an alias (mysql) with the primary name (mariadb.service).
        var id = target["Id"] ?? unit;
        var targetAfter = after.FirstOrDefault(u => u["Id"] == id) ?? target;
        var stopped = after
            .Where(u => u["Id"] is { } id && dependents.Contains(id) && u["ActiveState"] is "inactive" or "failed")
            .Select(u => u["Id"]!)
            .ToList();

        var statusBefore = Status(target);
        var statusAfter = Status(targetAfter);
        var detail = $"{verb}: {statusBefore} -> {statusAfter}.";
        if (stopped.Count > 0)
        {
            detail += $" Also stopped {stopped.Count} dependent service(s), which a restart of this one does NOT bring back: " +
                      $"{string.Join(", ", stopped)}.";
        }

        detail += stillRunning;
        if (stillRunning is null && action != ServiceAction.Stop && !statusAfter.StartsWith("active", StringComparison.Ordinal))
        {
            detail += $" The service did not reach active - check event_log_tail with unit='{unit}' for why.";
        }

        return new ServiceControlResult(unit, targetAfter["Description"], action, statusBefore, statusAfter, stopped, detail);
    }

    private async Task<IReadOnlyList<SystemdUnit>> ShowAsync(IReadOnlyList<string> units, CancellationToken cancellationToken)
    {
        var result = await commands.RunAsync(
            "systemctl", ["show", "-p", "Id,Names,Description,LoadState,ActiveState,SubState,SuccessAction,FailureAction,Requires", "--", .. units], QueryWait, cancellationToken)
            .ConfigureAwait(false);
        return result.ExitCode == 0
            ? SystemctlShow.Parse(result.StandardOutput)
            : throw new ServiceControlException($"systemctl show failed: {LinuxServiceInspector.FirstLine(result.StandardError)}");
    }

    /// <summary>The services that depend on this one and are active now: the ones a stop takes down with it.</summary>
    private async Task<List<string>> ActiveDependentsAsync(string unit, string verb, CancellationToken cancellationToken)
    {
        var result = await commands.RunAsync(
            "systemctl", ["list-dependencies", "--reverse", "--all", "--full", "--plain", "--no-legend", "--no-pager", "--", unit], QueryWait, cancellationToken)
            .ConfigureAwait(false);
        // Fail closed. list-dependencies exits non-zero with empty or partial output on a D-Bus timeout or when one
        // unit's properties fail part-way through the --all walk; read as "no dependents", that let through a stop
        // that took ssh.service or this server down with it. An unknown list cannot be shown free of critical units.
        if (result.ExitCode != 0)
        {
            throw new ServiceControlException(
                $"Refusing to {verb} '{unit}': could not list the services that depend on it " +
                $"(systemctl reported: {LinuxServiceInspector.FirstLine(result.StandardError)}). Nothing has been done.");
        }

        var names = result.StandardOutput
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Skip(1)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (names.Count == 0)
        {
            return [];
        }

        var shown = await ShowAsync(names, cancellationToken).ConfigureAwait(false);
        return shown.Where(u => u["ActiveState"] == "active" && u["Id"] is not null).Select(u => u["Id"]!).ToList();
    }

    private static string Status(SystemdUnit unit) => $"{unit["ActiveState"]} ({unit["SubState"]})";

    private static string? ReadSelfUnit()
    {
        try
        {
            var path = CgroupPath.Parse(ProcFiles.Read(ProcFiles.SelfCgroup));
            var last = path.Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault();
            return last?.EndsWith(".service", StringComparison.Ordinal) == true ? last : null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "service_control: {Action} {Unit}")]
    private static partial void LogChanged(ILogger logger, string action, string unit);
}
