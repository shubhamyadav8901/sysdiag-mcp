using System.Net;
using System.Net.Sockets;
using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Diagnostics;
using LinuxDiag.Mcp.Diagnostics.Containers;
using LinuxDiag.Mcp.Diagnostics.Network;
using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Tools;

namespace LinuxDiag.Mcp.Tests;

public sealed class NetworkTests
{
    // Captured from WSL Ubuntu's /proc/net/tcp.
    private const string Tcp =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
        "   0: 3600007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 31888 1 0000000000000000 100 0 0 10 5\n" +
        "   5: 8F28A8C0:9EBD 3000D417:0050 06 00000000:00000000 03:0000013D 00000000     0        0 0 3 0000000000000000\n";

    [Fact]
    public void Ipv4_addresses_are_little_endian_words_and_ports_are_hex()
    {
        var entries = SocketTable.Parse(Tcp);

        Assert.Equal(IPAddress.Parse("127.0.0.54"), entries[0].LocalAddress);
        Assert.Equal(53, entries[0].LocalPort);
        Assert.Equal(10, entries[0].State);
        Assert.Equal(31888, entries[0].Inode);
        Assert.Equal(IPAddress.Parse("192.168.40.143"), entries[1].LocalAddress);
        Assert.Equal(80, entries[1].RemotePort);
        Assert.Equal(0, entries[1].Inode); // TIME_WAIT: no socket, so no owner
    }

    [Fact]
    public void Ipv6_addresses_are_four_little_endian_words()
    {
        var entries = SocketTable.Parse(
            "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
            "   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9201 1 0000000000000000 100 0 0 10 0\n" +
            "   1: 0000000000000000FFFF00000100007F:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9202 1 0000000000000000 100 0 0 10 0\n");

        Assert.Equal(IPAddress.IPv6Loopback, entries[0].LocalAddress);
        Assert.Equal(8080, entries[0].LocalPort);
        Assert.Equal(IPAddress.Parse("::ffff:127.0.0.1"), entries[1].LocalAddress);
    }

    [Theory]
    [InlineData(10, "Listen")]
    [InlineData(1, "Established")]
    [InlineData(6, "TimeWait")]
    [InlineData(8, "CloseWait")]
    public void Tcp_states_use_windiags_names(int state, string name)
    {
        Assert.Equal(name, SocketTable.TcpStateName(state));
    }

    [Fact]
    public void Every_captured_distro_parses()
    {
        foreach (var distro in ProcParserTests.Distros())
        {
            foreach (var table in new[] { "net-tcp", "net-tcp6", "net-udp", "net-udp6" })
            {
                var text = ProcParserTests.Fixture(distro, table)!;
                Assert.Equal(text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length - 1, SocketTable.Parse(text).Count);
            }
        }
    }

    [Fact]
    public void A_shared_listener_lists_every_owner_and_unattributed_sockets_are_explained()
    {
        var owners = new List<SocketOwner> { new(10, "nginx", null), new(11, "nginx", null) };
        var endpoints = new NetworkEndpoints(
            [new NetworkEndpoint(TransportProtocol.Tcp, "0.0.0.0", 80, null, null, "Listen", owners, "net:[1]")],
            1, false, ["3 processes' open files could not be read."], "net:[1]");

        var summary = NetworkTools.RenderEndpoints(endpoints, null, null, false);

        Assert.Contains("nginx (PID 10), nginx (PID 11)", summary, StringComparison.Ordinal);
        Assert.StartsWith("WARNING: 3 processes", summary, StringComparison.Ordinal);
        Assert.DoesNotContain("netns", summary, StringComparison.Ordinal); // the server's own namespace is not tagged
    }

    [Fact]
    public void Two_processes_holding_one_socket_are_both_owners()
    {
        ProcessRecord Worker(int pid) => new(pid, 1, "nginx", "S", false, 1, DateTimeOffset.UnixEpoch, 0, 1, 0, null,
            "nginx", false, "/", null, null, "net:[1]", "mnt:[1]");
        var walk = new Diagnostics.Handles.DescriptorSnapshot(
            [new(Worker(10), 6, "socket:[500]"), new(Worker(11), 6, "socket:[500]"), new(Worker(10), 7, "socket:[500]")], 0);

        var owners = SocketOwners.ByInode(walk, new Dictionary<string, ContainerInfo>())[500];

        Assert.Equal([10, 11], owners.Select(o => o.ProcessId));
    }

    [LinuxFact]
    public async Task A_listener_this_process_opened_is_found_by_port_and_owned_by_this_process()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var options = LinuxDiagOptions.FromEnvironment(new System.Collections.Hashtable());

        var result = await new LinuxNetworkInspector(new LinuxProcessTable(), new LinuxContainerInspector(), options)
            .EndpointsAsync(port, null, listeningOnly: true, CancellationToken.None);

        var endpoint = Assert.Single(result.Endpoints);
        Assert.Equal("Listen", endpoint.State);
        Assert.Equal("127.0.0.1", endpoint.LocalAddress);
        Assert.Contains(endpoint.Owners, o => o.ProcessId == Environment.ProcessId);
    }
}
