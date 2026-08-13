using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using WinDiag.Mcp.Configuration;

namespace WinDiag.Mcp.Diagnostics.Dumps;

/// <summary>Writes dumps with <c>dbghelp!MiniDumpWriteDump</c>.</summary>
/// <remarks>
/// Chosen over shelling out to <c>procdump.exe</c> because it is the same underlying call without the
/// dependency, and because procdump's genuinely useful features — triggering on a CPU spike, on a hung
/// window, on an unhandled exception — are a different tool's job. This one answers "dump it now".
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class MiniDumpWriter : IDumpWriter
{
    /// <summary>Flags for <see cref="DumpKind.Mini"/>: everything useful except process memory.</summary>
    private const uint MiniFlags =
        MiniDumpWithHandleData | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules
        | MiniDumpWithProcessThreadData;

    /// <summary>Flags for <see cref="DumpKind.Full"/>.</summary>
    private const uint FullFlags = MiniFlags | MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo;

    private const uint MiniDumpWithFullMemory = 0x00000002;
    private const uint MiniDumpWithHandleData = 0x00000004;
    private const uint MiniDumpWithUnloadedModules = 0x00000020;
    private const uint MiniDumpWithProcessThreadData = 0x00000100;
    private const uint MiniDumpWithFullMemoryInfo = 0x00000800;
    private const uint MiniDumpWithThreadInfo = 0x00001000;

    private readonly WinDiagOptions _options;
    private readonly IPrivilegeProbe _privileges;

    public MiniDumpWriter(WinDiagOptions options, IPrivilegeProbe privileges)
    {
        _options = options;
        _privileges = privileges;
    }

    public DumpResult Capture(int processId, DumpKind kind, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // MiniDumpWriteDump suspends the target's threads, and when the target is us, one of those is
        // the thread making the call. It sometimes succeeds and sometimes deadlocks outright -- observed
        // here as a test run that passed in isolation and hung under parallel load. A hang inside a
        // long-lived elevated server is unrecoverable without killing it, so this is refused outright
        // rather than left as a race.
        if (processId == Environment.ProcessId)
        {
            throw new DumpCaptureException(
                "Refusing to dump this diagnostics server's own process. A process cannot reliably dump " +
                "itself -- the call suspends the very thread making it -- and a hang here would take the " +
                "server down. Use an external tool such as procdump if you need to debug windiag itself.");
        }

        using var process = OpenProcess(processId);
        var name = process.ProcessName;

        Directory.CreateDirectory(_options.ArtifactDirectory);

        // Timestamped rather than overwriting: capturing the same process twice while chasing an
        // intermittent fault is normal, and silently replacing the first capture would discard evidence.
        var fileName = string.Create(
            CultureInfo.InvariantCulture,
            $"{name}_{processId}_{DateTime.Now:yyyyMMdd_HHmmss}.dmp");

        var path = Path.Combine(_options.ArtifactDirectory, fileName);

        Write(process, processId, kind, path);

        var info = new FileInfo(path);
        if (!info.Exists || info.Length == 0)
        {
            throw new DumpCaptureException(
                $"MiniDumpWriteDump reported success but '{path}' is missing or empty.");
        }

        return new DumpResult(
            Path: path,
            UncPath: ToAdminShare(path),
            SizeBytes: info.Length,
            ProcessId: processId,
            ProcessName: name,
            Kind: kind,
            Elevated: _privileges.IsElevated,
            TargetIsWow64: IsWow64(process));
    }

    /// <summary>True when the target is a 32-bit process running under WOW64 on 64-bit Windows.</summary>
    /// <remarks>
    /// Worth reporting rather than silently producing a dump that reads oddly. A 64-bit dumper writing a
    /// 32-bit target yields a dump whose stacks show the WOW64 thunk layer by default; the analyst has to
    /// know to switch the debugger over. For this project that is the everyday case, not an edge case —
    /// Office add-ins and shell extensions routinely live in 32-bit hosts.
    /// </remarks>
    private static bool IsWow64(Process process)
    {
        if (!Environment.Is64BitOperatingSystem)
        {
            return false;
        }

        try
        {
            return IsWow64Process(process.Handle, out var wow64) && wow64;
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            // Not knowing the bitness is not a reason to fail a dump that already succeeded.
            return false;
        }
    }

    private void Write(Process process, int processId, DumpKind kind, string path)
    {
        SafeFileHandle handle;
        try
        {
            handle = File.Create(path).SafeFileHandle;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new DumpCaptureException(
                $"Could not create '{path}': {ex.Message}. Check WINDIAG_ARTIFACT_DIR is writable and " +
                "has room — a full dump can be several gigabytes.", ex);
        }

        using (handle)
        {
            var flags = kind == DumpKind.Full ? FullFlags : MiniFlags;

            if (MiniDumpWriteDump(process.Handle, (uint)processId, handle, flags,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
            {
                return;
            }

            var error = new Win32Exception(Marshal.GetLastWin32Error());

            // Delete the partial file rather than leaving something that looks like a dump but is not.
            TryDelete(path);

            throw new DumpCaptureException(
                $"MiniDumpWriteDump failed for PID {processId}: {error.Message}. " +
                (_privileges.IsElevated
                    ? "The process may be protected (anti-malware, LSA) or of a different bitness."
                    : "The server is NOT elevated, which is the usual cause when the target belongs to " +
                      "another user or to SYSTEM. Restart it from an elevated terminal."),
                error);
        }
    }

    private static Process OpenProcess(int processId)
    {
        try
        {
            var process = Process.GetProcessById(processId);

            // Touching Handle here surfaces an access failure as a clear error before a file is created.
            _ = process.Handle;
            return process;
        }
        catch (ArgumentException ex)
        {
            throw new DumpCaptureException(
                $"No process with PID {processId} is running. Call process_list to get a current PID — " +
                "PIDs are reused, so one read minutes ago may now be a different process.", ex);
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            throw new DumpCaptureException(
                $"Could not open PID {processId} for reading: {ex.Message}. Elevation is usually the " +
                "cause when the target belongs to another user.", ex);
        }
    }

    /// <summary>
    /// Rewrites a local path as an administrative-share path, so a debugger elsewhere can open it.
    /// </summary>
    /// <remarks>
    /// This is what makes the dump usable without copying gigabytes: <c>cdb</c> opens a UNC path
    /// directly, so the result feeds straight into mcp-windbg from the base machine. Reaching the
    /// admin share needs administrative credentials on this machine, which the operator has by
    /// construction — they started this server elevated.
    /// </remarks>
    internal static string? ToAdminShare(string path)
    {
        var root = Path.GetPathRoot(path);

        // Only a local drive letter maps to an admin share. A path already on a UNC share, or on a
        // volume with no drive letter, has no such translation.
        if (root is null || root.Length < 2 || root[1] != ':')
        {
            return null;
        }

        return $@"\\{Environment.MachineName}\{root[0]}$\{path[root.Length..]}";
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Reporting the original failure matters more than this one.
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWow64Process(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

    [DllImport("dbghelp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        uint processId,
        SafeFileHandle hFile,
        uint dumpType,
        IntPtr exceptionParam,
        IntPtr userStreamParam,
        IntPtr callbackParam);
}
