using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Extensions.Logging;

namespace WinDiag.Mcp.Diagnostics.Control;

/// <inheritdoc />
[SupportedOSPlatform("windows")]
public sealed class WindowsServiceControllerAdapter : IServiceController
{
    /// <summary>
    /// Services that must never be stopped or restarted through this tool.
    /// </summary>
    /// <remarks>
    /// Stopping any of these takes the machine out of service, and several take the diagnostics with
    /// them — stop <c>Winmgmt</c> and <c>process_list</c> stops working; stop <c>RpcSs</c> and
    /// essentially everything does. The list is short and hardcoded on purpose: a configurable
    /// safety list is one that eventually gets configured empty.
    /// </remarks>
    private static readonly HashSet<string> Critical = new(StringComparer.OrdinalIgnoreCase)
    {
        "RpcSs", "DcomLaunch", "RpcEptMapper", "LSM", "Power", "PlugPlay",
        "EventLog", "Winmgmt", "BFE", "mpssvc", "SamSs", "CryptSvc", "ProfSvc"
    };

    /// <summary>How long to wait for a state change before reporting it as not settled.</summary>
    private static readonly TimeSpan StateTimeout = TimeSpan.FromSeconds(45);

    private readonly ILogger<WindowsServiceControllerAdapter> _logger;

    public WindowsServiceControllerAdapter(ILogger<WindowsServiceControllerAdapter> logger)
    {
        _logger = logger;
    }

    public ServiceControlResult Control(string serviceName, ServiceAction action, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
        cancellationToken.ThrowIfCancellationRequested();

        if (action != ServiceAction.Start && Critical.Contains(serviceName))
        {
            throw new ServiceControlException(
                $"Refusing to {action.ToString().ToLowerInvariant()} '{serviceName}'. It is a core Windows " +
                "service; stopping it would take this machine out of service, and several on that list " +
                "would take these diagnostics down with it. Nothing has been done.");
        }

        using var service = Open(serviceName);
        var before = ReadStatus(service);
        var dependents = new List<string>();

        try
        {
            switch (action)
            {
                case ServiceAction.Start:
                    Start(service);
                    break;

                case ServiceAction.Stop:
                    dependents.AddRange(StopWithDependents(service));
                    break;

                case ServiceAction.Restart:
                    dependents.AddRange(StopWithDependents(service));
                    Start(service);
                    break;

                default:
                    throw new ServiceControlException($"'{action}' is not a supported action.");
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception
                                       or System.ServiceProcess.TimeoutException)
        {
            throw new ServiceControlException(
                $"Could not {action.ToString().ToLowerInvariant()} '{serviceName}': {ex.Message}", ex);
        }

        service.Refresh();
        var after = ReadStatus(service);

        _logger.LogWarning("{Action} service {Service}: {Before} -> {After}", action, serviceName, before, after);

        return new ServiceControlResult(
            ServiceName: service.ServiceName,
            DisplayName: service.DisplayName,
            Action: action,
            StatusBefore: before,
            StatusAfter: after,
            DependentServicesStopped: dependents,
            Detail: Describe(action, before, after, dependents));
    }

    /// <summary>
    /// Stops dependents first, because the SCM refuses to stop a service that others depend on.
    /// </summary>
    /// <remarks>
    /// Reported back explicitly: stopping one service can quietly take several down with it, and the
    /// caller needs to know what else it just turned off — restarting the named service does not
    /// necessarily bring the others back.
    /// </remarks>
    private static List<string> StopWithDependents(ServiceController service)
    {
        var stopped = new List<string>();

        // Names first, then a freshly opened controller for each. The instances handed back by
        // DependentServices share native state with the parent, so disposing one invalidates the
        // parent too - which surfaced as "Cannot access a disposed object" on the very next call,
        // after the dependents had already been stopped.
        var dependents = service.DependentServices.Select(d => d.ServiceName).ToArray();

        foreach (var name in dependents)
        {
            using var dependent = new ServiceController(name);

            if (dependent.Status == ServiceControllerStatus.Stopped)
            {
                continue;
            }

            dependent.Stop();
            dependent.WaitForStatus(ServiceControllerStatus.Stopped, StateTimeout);
            stopped.Add(name);
        }

        if (service.Status != ServiceControllerStatus.Stopped)
        {
            service.Stop();
            service.WaitForStatus(ServiceControllerStatus.Stopped, StateTimeout);
        }

        return stopped;
    }

    private static void Start(ServiceController service)
    {
        service.Refresh();
        if (service.Status is ServiceControllerStatus.Running)
        {
            return;
        }

        service.Start();
        service.WaitForStatus(ServiceControllerStatus.Running, StateTimeout);
    }

    private static ServiceController Open(string serviceName)
    {
        try
        {
            var service = new ServiceController(serviceName);
            _ = service.Status; // Touch it so a missing service fails here, before any action.
            return service;
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            throw new ServiceControlException(
                $"No service named '{serviceName}' exists, or it could not be opened. Call service_config " +
                "first to check the name - it takes the short name or the display name.", ex);
        }
    }

    private static string ReadStatus(ServiceController service)
    {
        try
        {
            service.Refresh();
            return service.Status.ToString();
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return "(unreadable)";
        }
    }

    private static string Describe(
        ServiceAction action, string before, string after, IReadOnlyList<string> dependents)
    {
        var detail = $"{action}: {before} -> {after}.";

        if (dependents.Count > 0)
        {
            detail += $" Also stopped {dependents.Count} dependent service(s), which a restart of this " +
                      "one does NOT bring back: " + string.Join(", ", dependents) + ".";
        }

        if (action != ServiceAction.Stop && after != nameof(ServiceControllerStatus.Running))
        {
            detail += " The service did not reach Running - check event_log_tail on the System log for why.";
        }

        return detail;
    }
}
