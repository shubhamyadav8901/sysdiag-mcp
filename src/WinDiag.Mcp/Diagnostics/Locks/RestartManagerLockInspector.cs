using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Logging;
using static WinDiag.Mcp.Diagnostics.Locks.RestartManagerInterop;

namespace WinDiag.Mcp.Diagnostics.Locks;

/// <summary>
/// Finds lock holders using the Restart Manager API, the same mechanism Explorer and Windows
/// Installer use to ask "who has this open?".
/// </summary>
/// <remarks>
/// <para><strong>Coverage is not exhaustive, by design of the underlying API.</strong> Restart Manager
/// exists to let installers avoid reboots, so it reports processes it could plausibly restart. It
/// reliably finds the common interactive case (an Office app, Explorer, a console tool holding a file)
/// and misses holders it cannot restart or does not track: many services, kernel-held references,
/// memory-mapped sections, and anything holding the file without participating in Restart Manager.</para>
/// <para>It is still the right default because it needs no elevation, loads no driver, and returns in
/// milliseconds. The caller is responsible for saying so when the result is empty -- see
/// <c>FileLockTools</c>, which points at the exhaustive handle.exe search instead.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class RestartManagerLockInspector : ILockInspector
{
    /// <summary>
    /// Tolerance when comparing a process start time against the one Restart Manager reported.
    /// </summary>
    /// <remarks>
    /// FILETIME and <see cref="Process.StartTime"/> come from the same kernel value but travel through
    /// different conversions, so an exact equality check produces spurious "PID was recycled" verdicts.
    /// </remarks>
    private static readonly TimeSpan StartTimeTolerance = TimeSpan.FromSeconds(2);

    private readonly ILogger<RestartManagerLockInspector> _logger;

    public RestartManagerLockInspector(ILogger<RestartManagerLockInspector> logger)
    {
        _logger = logger;
    }

    public LockQueryResult WhoLocks(string path, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        cancellationToken.ThrowIfCancellationRequested();

        var sessionKey = new StringBuilder(CchRmSessionKey + 1);
        var startResult = RmStartSession(out var session, 0, sessionKey);
        if (startResult != ErrorSuccess)
        {
            throw new LockQueryException(
                $"Could not start a Restart Manager session (Win32 error {startResult}). " +
                "This is an environment failure rather than a result: no conclusion about the file " +
                "should be drawn from it.");
        }

        try
        {
            var registerResult = RmRegisterResources(session, 1, [path], 0, null, 0, null);
            if (registerResult != ErrorSuccess)
            {
                throw new LockQueryException(
                    $"Restart Manager rejected the path '{path}' (Win32 error {registerResult}). " +
                    "Check that it exists and is a full path on a local volume.");
            }

            var holders = GetList(session, cancellationToken);
            return new LockQueryResult(path, holders, Exhaustive: false);
        }
        finally
        {
            RmEndSession(session);
        }
    }

    private List<LockHolder> GetList(uint session, CancellationToken cancellationToken)
    {
        uint arraySize = 0;
        uint rebootReasons = 0;

        // First call sizes the array. It is expected to fail with ERROR_MORE_DATA whenever there is at
        // least one holder.
        var result = RmGetList(session, out var needed, ref arraySize, null, ref rebootReasons);

        if (result == ErrorSuccess && needed == 0)
        {
            return [];
        }

        // ERROR_SUCCESS with a non-zero count is outside the documented contract for a sizing call,
        // but treating it as a failure would turn "here is how many there are" into a dead end.
        // Fall through and fetch them.
        if (result != ErrorMoreData && result != ErrorSuccess)
        {
            throw new LockQueryException(
                $"Restart Manager could not enumerate holders (Win32 error {result}).");
        }

        // Retry a bounded number of times: a holder appearing between the sizing call and the fetch
        // makes the buffer too small again. Bounded because an unbounded retry on a busy machine is a
        // hang, and this tool is on the interactive path.
        for (var attempt = 0; attempt < 4; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var buffer = new RmProcessInfo[needed];
            arraySize = needed;
            result = RmGetList(session, out needed, ref arraySize, buffer, ref rebootReasons);

            if (result == ErrorSuccess)
            {
                var holders = new List<LockHolder>((int)arraySize);
                for (var i = 0; i < arraySize; i++)
                {
                    holders.Add(Describe(buffer[i]));
                }

                return holders;
            }

            if (result != ErrorMoreData)
            {
                throw new LockQueryException(
                    $"Restart Manager could not enumerate holders (Win32 error {result}).");
            }

            _logger.LogDebug("Restart Manager holder list grew during enumeration; retrying (attempt {Attempt})", attempt + 1);
        }

        throw new LockQueryException(
            "Restart Manager's holder list kept growing while being read, so no stable answer could be " +
            "produced. Retry, or use the exhaustive handle search.");
    }

    private static LockHolder Describe(in RmProcessInfo info)
    {
        var startedAt = ToDateTimeOffset(info.Process.ProcessStartTime);
        var (name, stillRunning) = ResolveProcess(info.Process.dwProcessId, startedAt);

        return new LockHolder(
            ProcessId: info.Process.dwProcessId,
            ProcessName: name,
            FriendlyName: NullIfEmpty(info.strAppName),
            ServiceShortName: NullIfEmpty(info.strServiceShortName),
            Kind: MapKind(info.ApplicationType),
            StartedAt: startedAt,
            StillRunning: stillRunning);
    }

    /// <summary>
    /// True when a live process's start time is too far from the reported one to be the same process.
    /// </summary>
    /// <remarks>Internal so the recycling rule can be tested without contriving real PID reuse.</remarks>
    internal static bool IsPidReused(DateTimeOffset? reportedStart, DateTimeOffset actualStart) =>
        reportedStart is { } expected && (actualStart - expected).Duration() > StartTimeTolerance;

    /// <summary>Resolves the image name, refusing to trust a PID whose start time no longer matches.</summary>
    private static (string Name, bool StillRunning) ResolveProcess(int processId, DateTimeOffset? startedAt)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            var actual = new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero);

            if (IsPidReused(startedAt, actual))
            {
                // The PID has been reused since Restart Manager reported it. Returning the current
                // occupant's name would name an innocent process as the lock holder.
                return ("(exited, PID reused)", false);
            }

            return (process.ProcessName, true);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return ("(exited)", false);
        }
        catch (Win32Exception)
        {
            // Access denied reading a more privileged process: it is running, we just cannot name it.
            return ("(access denied)", true);
        }
    }

    private static DateTimeOffset? ToDateTimeOffset(FILETIME fileTime)
    {
        var ticks = ((long)(uint)fileTime.dwHighDateTime << 32) | (uint)fileTime.dwLowDateTime;
        if (ticks == 0)
        {
            return null;
        }

        try
        {
            return DateTimeOffset.FromFileTime(ticks).ToUniversalTime();
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static LockHolderKind MapKind(RmAppType type) => type switch
    {
        RmAppType.RmMainWindow => LockHolderKind.MainWindow,
        RmAppType.RmOtherWindow => LockHolderKind.OtherWindow,
        RmAppType.RmService => LockHolderKind.Service,
        RmAppType.RmExplorer => LockHolderKind.Explorer,
        RmAppType.RmConsole => LockHolderKind.Console,
        RmAppType.RmCritical => LockHolderKind.Critical,
        _ => LockHolderKind.Unknown
    };

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
