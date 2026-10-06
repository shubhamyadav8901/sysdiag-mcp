using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace WinDiag.Mcp.Diagnostics.Control;

/// <inheritdoc />
/// <remarks>
/// The service list comes from the SCM rather than WMI's Win32_Service.ProcessId: it is the same answer in
/// milliseconds instead of seconds, and it does not depend on Winmgmt -- one of the services whose host this
/// check exists to protect.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsProcessProtectionProbe : IProcessProtectionProbe
{
    private const uint ScManagerEnumerateService = 0x0004;
    private const int ScEnumProcessInfo = 0;
    private const uint ServiceWin32 = 0x30;
    private const uint ServiceActive = 0x1;
    private const int ErrorMoreData = 234;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    /// <summary>The first batch's buffer; a typical machine's whole list fits, so one call usually does.</summary>
    private readonly int _initialBufferBytes;

    public WindowsProcessProtectionProbe()
        : this(64 * 1024)
    {
    }

    /// <summary>A probe whose first batch is <paramref name="initialBufferBytes"/> long.</summary>
    /// <remarks>
    /// Internal so a test can make the list arrive in several batches. With the default, the resume path
    /// never runs on a machine with an ordinary number of services, and a mistake in it would go unseen until
    /// one with many more -- where it would drop the services of the first batch, RpcSs's host among them.
    /// </remarks>
    internal WindowsProcessProtectionProbe(int initialBufferBytes) => _initialBufferBytes = initialBufferBytes;

    public IReadOnlyList<string> ServicesHostedBy(int processId) =>
        ActiveServices().Where(s => s.ProcessId == processId).Select(s => s.Name).ToList();

    /// <remarks>
    /// Opens its own handle with the one right IsProcessCritical needs. Process.Handle asks for
    /// PROCESS_ALL_ACCESS, which a protected process -- wininit, csrss, smss and services are all critical and
    /// all protected -- refuses even to an elevated caller holding SeDebugPrivilege, so the probe failed on
    /// exactly the processes it is about. The PID is safe to reopen while the caller holds the Process: an open
    /// handle keeps the PID from being reused.
    /// </remarks>
    public bool IsCritical(Process process)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, (uint)process.Id);
        if (handle == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            if (!IsProcessCritical(handle, out var critical))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return critical;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    /// <summary>Every running Win32 service with the PID that hosts it, from the SCM.</summary>
    internal IReadOnlyList<(string Name, int ProcessId)> ActiveServices()
    {
        var manager = OpenSCManagerW(null, null, ScManagerEnumerateService);
        if (manager == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            return Enumerate(manager, _initialBufferBytes);
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    private static List<(string Name, int ProcessId)> Enumerate(IntPtr manager, int initialBufferBytes)
    {
        var services = new List<(string, int)>();
        var stride = Marshal.SizeOf<EnumServiceStatusProcess>();
        uint resume = 0;
        var size = initialBufferBytes;

        while (true)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var done = EnumServicesStatusExW(
                    manager, ScEnumProcessInfo, ServiceWin32, ServiceActive, buffer, (uint)size,
                    out var needed, out var returned, ref resume, null);
                var error = Marshal.GetLastWin32Error();

                // A partial batch still carries its entries; the resume handle picks up after them.
                for (var i = 0; i < returned; i++)
                {
                    var entry = Marshal.PtrToStructure<EnumServiceStatusProcess>(buffer + i * stride);
                    services.Add((Marshal.PtrToStringUni(entry.ServiceName) ?? string.Empty, (int)entry.ProcessId));
                }

                if (done)
                {
                    return services;
                }

                if (error != ErrorMoreData)
                {
                    throw new Win32Exception(error);
                }

                size = Math.Max(size, (int)needed);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    /// <summary>ENUM_SERVICE_STATUS_PROCESSW: two string pointers, then SERVICE_STATUS_PROCESS.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct EnumServiceStatusProcess
    {
        public IntPtr ServiceName;
        public IntPtr DisplayName;
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumServicesStatusExW(
        IntPtr manager,
        int infoLevel,
        uint serviceType,
        uint serviceState,
        IntPtr services,
        uint bufferSize,
        out uint bytesNeeded,
        out uint servicesReturned,
        ref uint resumeHandle,
        string? groupName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessCritical(IntPtr process, [MarshalAs(UnmanagedType.Bool)] out bool critical);
}
