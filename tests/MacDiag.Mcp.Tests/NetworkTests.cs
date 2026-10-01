using System.Collections;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Network;
using static MacDiag.Mcp.Tests.LsofTests;

namespace MacDiag.Mcp.Tests;

public sealed class NetworkTests
{
    private static MacDiagOptions Options() => MacDiagOptions.FromEnvironment(new Hashtable());

    private static Task<NetworkEndpoints> Endpoints(int? port = null, int? processId = null, bool listeningOnly = false) =>
        new MacNetworkInspector(new FakeCommands((_, _) => FakeCommands.Ok(RawFixture("lsof-i"))), Options())
            .EndpointsAsync(port, processId, listeningOnly, CancellationToken.None);

    [Theory]
    [InlineData("*:22", "*", 22, null, null)]
    [InlineData("[::1]:8080->[::1]:51234", "::1", 8080, "::1", 51234)]
    [InlineData("10.0.0.5:443->10.0.0.9:60000", "10.0.0.5", 443, "10.0.0.9", 60000)]
    [InlineData("[fe80::1%lo0]:5353", "fe80::1%lo0", 5353, null, null)]
    public void Lsof_addresses_split_into_both_ends(string name, string local, int localPort, string? remote, int? remotePort)
    {
        Assert.Equal((local, localPort, remote, remotePort), LsofAddress.Parse(name));
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("*:*")]
    [InlineData("1.2.3.4:http")]
    public void An_address_in_another_shape_is_not_guessed(string name)
    {
        Assert.Null(LsofAddress.Parse(name));
    }

    [Fact]
    public async Task One_socket_shared_by_prefork_workers_is_one_endpoint_and_ipv4_and_ipv6_listeners_stay_apart()
    {
        var all = await Endpoints();

        var port80 = all.Endpoints.Where(e => e.LocalPort == 80).ToList();
        Assert.Equal(2, port80.Count);
        Assert.Contains(port80, e => e.Owners.Select(o => o.ProcessId).SequenceEqual([91, 92]));
        Assert.Contains(port80, e => e.Owners.Select(o => o.ProcessId).SequenceEqual([92]));
    }

    [Fact]
    public async Task Tcp_states_read_as_every_server_spells_them_and_udp_has_none()
    {
        var all = await Endpoints();

        Assert.Equal("Listen", all.Endpoints.Single(e => e.LocalPort == 22).State);
        Assert.Equal("Established", all.Endpoints.Single(e => e.RemotePort == 51234).State);
        var mdns = all.Endpoints.Single(e => e.LocalPort == 5353);
        Assert.Equal(TransportProtocol.Udp, mdns.Protocol);
        Assert.Null(mdns.State);
    }

    [Fact]
    public async Task An_address_the_server_cannot_read_is_counted_never_dropped_silently()
    {
        var all = await Endpoints();

        Assert.Equal(6, all.TotalMatched);
        Assert.Contains(all.Limitations, l => l.Contains("1 socket", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Filters_by_port_owner_and_listening_and_orders_by_protocol_then_port()
    {
        Assert.Equal(8080, Assert.Single((await Endpoints(port: 51234)).Endpoints).LocalPort);
        Assert.All((await Endpoints(processId: 92)).Endpoints, e => Assert.Contains(e.Owners, o => o.ProcessId == 92));
        Assert.DoesNotContain((await Endpoints(listeningOnly: true)).Endpoints, e => e.State == "Established");
        Assert.Equal([22, 80, 80, 8080, 8080, 5353], (await Endpoints()).Endpoints.Select(e => e.LocalPort));
    }

    private const string Listing =
        "p10\0cmDNSResponder\0u65\0\nf5\0au\0tunix\0d0x1\0n/private/var/run/mDNSResponder\0\n" +
        "p20\0cclient\0u501\0\nf7\0au\0tunix\0d0x2\0n/private/var/run/mDNSResponder\0\nf8\0au\0tunix\0d0x3\0n->0x1\0\n" +
        "p30\0creader\0u501\0\nf3\0ar\0tFIFO\0d0x4\0n/private/tmp/myfifo\0\nf4\0ar\0tREG\0n/private/tmp/other\0\n";

    private static Task<NamedPipeList> Pipes(string? nameFilter = null) =>
        new MacPipeInspector(new FakeCommands((_, _) => FakeCommands.Ok(Listing)), Options()).ListAsync(nameFilter, CancellationToken.None);

    [Fact]
    public async Task Named_sockets_and_fifos_are_listed_by_name_with_every_holder_and_unnamed_peers_are_left_out()
    {
        var pipes = await Pipes();

        Assert.Equal(["/private/tmp/myfifo", "/private/var/run/mDNSResponder"], pipes.Pipes.Select(p => p.Name));
        var socket = pipes.Pipes.Single(p => p.Kind == "UnixSocket");
        Assert.Equal([10, 20], socket.Owners.Select(o => o.ProcessId));
        Assert.Equal(2, socket.ConnectedCount);
        Assert.Null(socket.Listening);
        Assert.Equal("Fifo", pipes.Pipes.Single(p => p.Name.EndsWith("myfifo", StringComparison.Ordinal)).Kind);
    }

    [Fact]
    public async Task Every_answer_says_listening_state_is_not_visible_and_the_filter_matches_the_name()
    {
        var pipes = await Pipes("MDNS");

        Assert.Equal(["/private/var/run/mDNSResponder"], pipes.Pipes.Select(p => p.Name));
        Assert.Contains(pipes.Limitations, l => l.Contains("does not report whether a unix socket is listening", StringComparison.Ordinal));
    }
}
