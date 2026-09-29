using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using WinDiag.Mcp.Configuration;

namespace WinDiag.Mcp.Diagnostics.Network;

/// <summary>
/// Enumerates endpoints via IP Helper's extended tables, which carry the owning process id.
/// </summary>
/// <remarks>
/// The owning PID is the whole point, and it is why this uses <c>GetExtendedTcpTable</c> rather than
/// .NET's <c>IPGlobalProperties</c>: the managed API reports connections without saying who owns them,
/// which answers the less useful half of "what is talking to that address?".
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class IpHelperNetworkInspector : INetworkInspector
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint NoError = 0;

    private readonly WinDiagOptions _options;

    public IpHelperNetworkInspector(WinDiagOptions options)
    {
        _options = options;
    }

    public NetworkEndpointsResult List(
        int? port,
        int? processId,
        bool listeningOnly,
        CancellationToken cancellationToken)
    {
        var endpoints = new List<NetworkEndpoint>();

        endpoints.AddRange(ReadTcp(AfInet, cancellationToken));
        endpoints.AddRange(ReadTcp(AfInet6, cancellationToken));
        endpoints.AddRange(ReadUdp(AfInet, cancellationToken));
        endpoints.AddRange(ReadUdp(AfInet6, cancellationToken));

        Enrich(endpoints);

        IEnumerable<NetworkEndpoint> matched = endpoints;

        if (port is { } wanted)
        {
            matched = matched.Where(e => e.LocalPort == wanted || e.RemotePort == wanted);
        }

        if (processId is { } pid)
        {
            matched = matched.Where(e => e.OwningProcessId == pid);
        }

        if (listeningOnly)
        {
            matched = matched.Where(e => e.State is "Listen" || e.Protocol == TransportProtocol.Udp);
        }

        var ordered = matched
            .OrderBy(e => e.Protocol)
            .ThenBy(e => e.LocalPort)
            .ThenBy(e => e.OwningProcessId)
            .ToList();

        var truncated = ordered.Count > _options.MaxResults;

        return new NetworkEndpointsResult(
            truncated ? ordered.Take(_options.MaxResults).ToArray() : ordered,
            ordered.Count,
            truncated);
    }

    /// <summary>Attaches process names, opening each distinct PID at most once.</summary>
    private static void Enrich(List<NetworkEndpoint> endpoints)
    {
        var names = new Dictionary<int, string?>();

        for (var i = 0; i < endpoints.Count; i++)
        {
            var endpoint = endpoints[i];

            if (!names.TryGetValue(endpoint.OwningProcessId, out var name))
            {
                name = ResolveProcessName(endpoint.OwningProcessId);
                names[endpoint.OwningProcessId] = name;
            }

            endpoints[i] = endpoint with { ProcessName = name };
        }
    }

    private static string? ResolveProcessName(int processId)
    {
        // PID 0 is the system idle process and 4 is System; neither can be opened, and both legitimately
        // own endpoints (SMB, for instance), so they are named rather than left blank.
        switch (processId)
        {
            case 0:
                return "System Idle Process";
            case 4:
                return "System";
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            return process.ProcessName;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    private static List<NetworkEndpoint> ReadTcp(int addressFamily, CancellationToken cancellationToken)
    {
        var endpoints = new List<NetworkEndpoint>();
        var isIpv6 = addressFamily == AfInet6;
        var rowSize = isIpv6 ? 56 : 24;

        WithTable(
            (IntPtr buffer, ref int size) =>
                GetExtendedTcpTable(buffer, ref size, false, addressFamily, TcpTableOwnerPidAll, 0),
            (buffer, count) =>
            {
                var row = buffer + 4;

                for (var i = 0; i < count; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    endpoints.Add(isIpv6 ? ReadTcp6Row(row) : ReadTcp4Row(row));
                    row += rowSize;
                }
            });

        return endpoints;
    }

    private static List<NetworkEndpoint> ReadUdp(int addressFamily, CancellationToken cancellationToken)
    {
        var endpoints = new List<NetworkEndpoint>();
        var isIpv6 = addressFamily == AfInet6;
        var rowSize = isIpv6 ? 28 : 12;

        WithTable(
            (IntPtr buffer, ref int size) =>
                GetExtendedUdpTable(buffer, ref size, false, addressFamily, UdpTableOwnerPid, 0),
            (buffer, count) =>
            {
                var row = buffer + 4;

                for (var i = 0; i < count; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    endpoints.Add(isIpv6 ? ReadUdp6Row(row) : ReadUdp4Row(row));
                    row += rowSize;
                }
            });

        return endpoints;
    }

    /// <summary>
    /// Runs the size-then-fetch dance these APIs require, and hands the caller the row array.
    /// </summary>
    /// <remarks>
    /// The table can grow between the sizing call and the fetch on a busy machine, so the fetch is
    /// retried a bounded number of times rather than assuming the first size holds.
    /// </remarks>
    private static void WithTable(TableQuery query, Action<IntPtr, int> readRows)
    {
        // Sizing call. The size must travel by reference: passing it by value would discard the
        // required length the API writes back, and the fetch would then always run against a zero
        // buffer -- reading as "no connections on this machine".
        var bytes = 0;
        var status = query(IntPtr.Zero, ref bytes);

        if (status != ErrorInsufficientBuffer && status != NoError)
        {
            throw new NetworkQueryException($"Could not size the connection table (Win32 error {status}).");
        }

        if (bytes <= 0)
        {
            return;
        }

        for (var attempt = 0; attempt < 4; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(bytes);

            try
            {
                status = query(buffer, ref bytes);

                if (status == NoError)
                {
                    readRows(buffer, Marshal.ReadInt32(buffer));
                    return;
                }

                if (status != ErrorInsufficientBuffer)
                {
                    throw new NetworkQueryException($"Could not read the connection table (Win32 error {status}).");
                }

                // The table grew between sizing and fetching; `bytes` now holds the new requirement.
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        throw new NetworkQueryException(
            "The connection table kept growing while being read, so no stable snapshot could be taken.");
    }

    /// <summary>Signature shared by the two IP Helper table functions.</summary>
    private delegate uint TableQuery(IntPtr buffer, ref int size);

    private static NetworkEndpoint ReadTcp4Row(IntPtr row)
    {
        var state = DescribeState(Marshal.ReadInt32(row, 0));
        var listening = IsListening(state);

        return new NetworkEndpoint(
            TransportProtocol.Tcp,
            FormatIpv4(Marshal.ReadInt32(row, 4)),
            ReadPort(row, 8),
            listening ? null : FormatIpv4(Marshal.ReadInt32(row, 12)),
            listening ? null : ReadPort(row, 16),
            state,
            Marshal.ReadInt32(row, 20),
            null);
    }

    private static NetworkEndpoint ReadTcp6Row(IntPtr row)
    {
        var state = DescribeState(Marshal.ReadInt32(row, 48));
        var listening = IsListening(state);

        return new NetworkEndpoint(
            TransportProtocol.Tcp,
            FormatIpv6(row, 0, Marshal.ReadInt32(row, 16)),
            ReadPort(row, 20),
            listening ? null : FormatIpv6(row, 24, Marshal.ReadInt32(row, 40)),
            listening ? null : ReadPort(row, 44),
            state,
            Marshal.ReadInt32(row, 52),
            null);
    }

    /// <summary>
    /// A listening socket has no peer, so its remote fields are meaningless rather than zero.
    /// </summary>
    /// <remarks>
    /// The kernel leaves them as zeros, which would otherwise render as "-> 0.0.0.0:0" on every
    /// listener and, worse, make a search for port 0 match every listening socket on the machine.
    /// </remarks>
    private static bool IsListening(string state) => state is "Listen";

    private static NetworkEndpoint ReadUdp4Row(IntPtr row) =>
        new(
            TransportProtocol.Udp,
            FormatIpv4(Marshal.ReadInt32(row, 0)),
            ReadPort(row, 4),
            null,
            null,
            null,
            Marshal.ReadInt32(row, 8),
            null);

    private static NetworkEndpoint ReadUdp6Row(IntPtr row) =>
        new(
            TransportProtocol.Udp,
            FormatIpv6(row, 0, Marshal.ReadInt32(row, 16)),
            ReadPort(row, 20),
            null,
            null,
            null,
            Marshal.ReadInt32(row, 24),
            null);

    /// <summary>
    /// Reads a port field, which these structures store in network byte order in the low two bytes.
    /// </summary>
    /// <remarks>
    /// Reading the DWORD directly yields values like 20480 for port 80. Getting this wrong produces
    /// numbers that look like plausible high ports rather than an obvious error.
    /// </remarks>
    private static int ReadPort(IntPtr row, int offset)
    {
        var raw = Marshal.ReadInt32(row, offset);
        return IPAddress.NetworkToHostOrder((short)(raw & 0xFFFF)) & 0xFFFF;
    }

    private static string FormatIpv4(int address) => new IPAddress((uint)address & 0xFFFFFFFF).ToString();

    private static string FormatIpv6(IntPtr row, int offset, int scopeId)
    {
        var bytes = new byte[16];
        Marshal.Copy(row + offset, bytes, 0, 16);
        return new IPAddress(bytes, (uint)scopeId).ToString();
    }

    private static string DescribeState(int state) => state switch
    {
        1 => "Closed",
        2 => "Listen",
        3 => "SynSent",
        4 => "SynReceived",
        5 => "Established",
        6 => "FinWait1",
        7 => "FinWait2",
        8 => "CloseWait",
        9 => "Closing",
        10 => "LastAck",
        11 => "TimeWait",
        12 => "DeleteTcb",
        _ => $"(state {state})"
    };

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int pdwSize, [MarshalAs(UnmanagedType.Bool)] bool bOrder,
        int ulAf, int tableClass, int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref int pdwSize, [MarshalAs(UnmanagedType.Bool)] bool bOrder,
        int ulAf, int tableClass, int reserved);
}

/// <summary>Raised when the connection tables could not be read.</summary>
public sealed class NetworkQueryException : Exception, IDiagnosticException
{
    public NetworkQueryException(string message) : base(message)
    {
    }
}
