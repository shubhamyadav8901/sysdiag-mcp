using System.Globalization;
using System.Management;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using WinDiag.Mcp.Configuration;

namespace WinDiag.Mcp.Diagnostics.Processes;

/// <summary>
/// Lists processes via WMI, falling back to the managed <see cref="System.Diagnostics.Process"/> API.
/// </summary>
/// <remarks>
/// WMI is the primary source because <c>Win32_Process</c> carries the two fields that make a process
/// list worth having -- the full command line and the parent PID -- and neither is available from the
/// managed API without further interop. Which <c>svchost.exe</c> is misbehaving is a command-line
/// question, not a name question.
/// <para>WMI can be broken or disabled on a damaged machine, which is exactly when someone is looking
/// at a process list, so a failure degrades to the managed enumeration and says what was lost rather
/// than returning nothing.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WmiProcessInspector : IProcessInspector
{
    private const string Query =
        "SELECT ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath, CreationDate, " +
        "WorkingSetSize, ThreadCount, SessionId FROM Win32_Process";

    private readonly WinDiagOptions _options;
    private readonly ILogger<WmiProcessInspector> _logger;

    public WmiProcessInspector(WinDiagOptions options, ILogger<WmiProcessInspector> logger)
    {
        _options = options;
        _logger = logger;
    }

    public ProcessListResult List(string? nameFilter, int? processId, CancellationToken cancellationToken)
    {
        List<ProcessInfo> processes;
        string? limitation = null;

        try
        {
            processes = QueryWmi(cancellationToken);
        }
        catch (Exception ex) when (ex is ManagementException
                                      or UnauthorizedAccessException
                                      or System.Runtime.InteropServices.COMException)
        {
            _logger.LogWarning("WMI process query failed ({Reason}); falling back to the managed API", ex.Message);
            processes = QueryManaged(cancellationToken);
            limitation = "WMI was unavailable, so command lines and parent process ids could not be read. " +
                         $"Underlying error: {ex.Message}";
        }

        return Shape(processes, nameFilter, processId, limitation);
    }

    private ProcessListResult Shape(
        List<ProcessInfo> processes,
        string? nameFilter,
        int? processId,
        string? limitation)
    {
        IEnumerable<ProcessInfo> matched = processes;

        if (processId is { } pid)
        {
            matched = matched.Where(p => p.ProcessId == pid);
        }

        if (!string.IsNullOrWhiteSpace(nameFilter))
        {
            matched = matched.Where(p =>
                p.Name.Contains(nameFilter, StringComparison.OrdinalIgnoreCase)
                || (p.CommandLine?.Contains(nameFilter, StringComparison.OrdinalIgnoreCase) ?? false));
        }

        var ordered = matched
            .OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.ProcessId)
            .ToList();

        var truncated = ordered.Count > _options.MaxResults;

        return new ProcessListResult(
            Processes: truncated ? ordered.Take(_options.MaxResults).ToArray() : ordered,
            TotalMatched: ordered.Count,
            Truncated: truncated,
            CommandLinesRedacted: ordered.Count(p => p.CommandLine is null),
            Limitation: limitation);
    }

    private static List<ProcessInfo> QueryWmi(CancellationToken cancellationToken)
    {
        var processes = new List<ProcessInfo>();

        using var searcher = new ManagementObjectSearcher(Query);
        using var results = searcher.Get();

        foreach (var item in results)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var process = (ManagementObject)item;

            processes.Add(new ProcessInfo(
                ProcessId: ToInt32(process["ProcessId"]) ?? 0,
                ParentProcessId: ToInt32(process["ParentProcessId"]),
                Name: process["Name"] as string ?? "(unknown)",
                StartTime: ToDateTime(process["CreationDate"] as string),
                WorkingSetBytes: ToInt64(process["WorkingSetSize"]) ?? 0,
                ThreadCount: ToInt32(process["ThreadCount"]) ?? 0,
                SessionId: ToInt32(process["SessionId"]),
                ExecutablePath: process["ExecutablePath"] as string,
                CommandLine: process["CommandLine"] as string));
        }

        return processes;
    }

    private static List<ProcessInfo> QueryManaged(CancellationToken cancellationToken)
    {
        var processes = new List<ProcessInfo>();

        foreach (var process in System.Diagnostics.Process.GetProcesses())
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                processes.Add(new ProcessInfo(
                    ProcessId: process.Id,
                    ParentProcessId: null,
                    Name: process.ProcessName,
                    StartTime: SafeStartTime(process),
                    WorkingSetBytes: process.WorkingSet64,
                    ThreadCount: process.Threads.Count,
                    SessionId: process.SessionId,
                    ExecutablePath: null,
                    CommandLine: null));
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // Exited between enumeration and inspection, or protected. Skip it rather than fail
                // the whole listing.
            }
            finally
            {
                process.Dispose();
            }
        }

        return processes;
    }

    private static DateTimeOffset? SafeStartTime(System.Diagnostics.Process process)
    {
        try
        {
            return new DateTimeOffset(process.StartTime);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

    /// <summary>Converts a CIM_DATETIME string such as <c>20260811103000.000000+330</c>.</summary>
    internal static DateTimeOffset? ToDateTime(string? cimDateTime)
    {
        if (string.IsNullOrWhiteSpace(cimDateTime) || cimDateTime.Length < 21)
        {
            return null;
        }

        try
        {
            return new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(cimDateTime));
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or FormatException)
        {
            return null;
        }
    }

    private static int? ToInt32(object? value) =>
        value is null ? null : Convert.ToInt32(value, CultureInfo.InvariantCulture);

    private static long? ToInt64(object? value) =>
        value is null ? null : Convert.ToInt64(value, CultureInfo.InvariantCulture);
}
