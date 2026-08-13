using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Win32;

namespace WinDiag.Mcp.Diagnostics.Services;

/// <inheritdoc />
/// <remarks>
/// Configuration is read from the registry rather than through <c>QueryServiceConfig</c>: it needs no
/// P/Invoke, and it exposes fields the managed API omits, notably <c>DelayedAutostart</c> -- which is
/// frequently the answer to "the service is set to Automatic, so why did it start late?".
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsServiceInspector : IServiceInspector
{
    private const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";
    private const int MaxCandidates = 15;

    public ServiceQueryResult Query(string nameOrDisplayName, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nameOrDisplayName);
        cancellationToken.ThrowIfCancellationRequested();

        // GetServices() returns SERVICE_WIN32 only. Drivers live behind GetDevices(), and on an
        // ordinary workstation they outnumber services (471 devices against 321 services here).
        // Querying only the first makes every driver -- Tcpip, a filter driver, a vendor's kernel
        // component -- answer "no such service exists", which is the wrong answer to a question
        // people ask constantly when debugging a driver that failed to load.
        var win32 = ServiceController.GetServices();

        ServiceController[] drivers;
        try
        {
            drivers = ServiceController.GetDevices();
        }
        catch
        {
            // The first array is already allocated and holds native SCM handles; a failure here would
            // otherwise leak all ~320 of them in a long-lived elevated process.
            DisposeAll(win32);
            throw;
        }

        var services = win32.Concat(drivers).ToArray();

        try
        {
            var match = FindExact(services, nameOrDisplayName);
            if (match is null)
            {
                return new ServiceQueryResult(nameOrDisplayName, null, FindCandidates(services, nameOrDisplayName));
            }

            return new ServiceQueryResult(nameOrDisplayName, Describe(match), []);
        }
        finally
        {
            DisposeAll(services);
        }
    }

    private static void DisposeAll(IEnumerable<ServiceController> services)
    {
        foreach (var service in services)
        {
            service.Dispose();
        }
    }

    private static ServiceController? FindExact(ServiceController[] services, string query) =>
        services.FirstOrDefault(s => string.Equals(s.ServiceName, query, StringComparison.OrdinalIgnoreCase))
        ?? services.FirstOrDefault(s => string.Equals(s.DisplayName, query, StringComparison.OrdinalIgnoreCase));

    private static List<string> FindCandidates(ServiceController[] services, string query) =>
        services
            .Where(s => s.ServiceName.Contains(query, StringComparison.OrdinalIgnoreCase)
                        || s.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase))
            .Select(s => $"{s.ServiceName} ({s.DisplayName})")
            .Order(StringComparer.OrdinalIgnoreCase)
            .Take(MaxCandidates)
            .ToList();

    private static ServiceInfo Describe(ServiceController service)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"{ServicesKey}\{service.ServiceName}");

        return new ServiceInfo(
            ServiceName: service.ServiceName,
            DisplayName: NullIfEmpty(service.DisplayName),
            Description: NullIfEmpty(key?.GetValue("Description") as string),
            Status: SafeRead(() => service.Status.ToString(), "(unreadable)"),
            StartType: DescribeStartType(key?.GetValue("Start") as int?),
            DelayedAutoStart: (key?.GetValue("DelayedAutostart") as int?) == 1,
            ServiceType: DescribeServiceType(key?.GetValue("Type") as int?),

            // The raw value is intentionally not expanded: seeing the literal %SystemRoot% is useful
            // when diagnosing a service whose path was tampered with.
            ImagePath: NullIfEmpty(key?.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string),
            Account: NullIfEmpty(key?.GetValue("ObjectName") as string),
            DependsOn: key?.GetValue("DependOnService") as string[] ?? [],
            DependedOnBy: SafeRead(ReadDependents, (string[])[]));

        // DependentServices allocates fresh ServiceControllers, each holding a native SCM handle.
        // This inspector is a singleton and service_config is callable without limit, so leaking one
        // handle per dependent per call accumulates indefinitely in a long-lived elevated process.
        string[] ReadDependents()
        {
            var dependents = service.DependentServices;

            try
            {
                return dependents.Select(d => d.ServiceName).Order(StringComparer.OrdinalIgnoreCase).ToArray();
            }
            finally
            {
                DisposeAll(dependents);
            }
        }
    }

    /// <summary>
    /// Reads a property that can throw when the service is in a transitional or inaccessible state.
    /// </summary>
    /// <remarks>
    /// A service that stops between enumeration and inspection would otherwise fail the whole query,
    /// discarding the fields that were read successfully.
    /// </remarks>
    private static T SafeRead<T>(Func<T> read, T fallback)
    {
        try
        {
            return read();
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return fallback;
        }
    }

    private static string DescribeStartType(int? start) => start switch
    {
        0 => "Boot",
        1 => "System",
        2 => "Automatic",
        3 => "Manual",
        4 => "Disabled",
        null => "(unknown)",
        _ => $"(unrecognised: {start})"
    };

    private static string DescribeServiceType(int? type)
    {
        if (type is null)
        {
            return "(unknown)";
        }

        var names = new List<string>();

        if ((type & 0x1) != 0) names.Add("KernelDriver");
        if ((type & 0x2) != 0) names.Add("FileSystemDriver");
        if ((type & 0x10) != 0) names.Add("Win32OwnProcess");
        if ((type & 0x20) != 0) names.Add("Win32ShareProcess");
        if ((type & 0x100) != 0) names.Add("InteractiveProcess");

        return names.Count > 0 ? string.Join('|', names) : $"(unrecognised: {type})";
    }

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
