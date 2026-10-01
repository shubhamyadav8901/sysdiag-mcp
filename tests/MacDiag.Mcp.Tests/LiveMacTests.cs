using System.Collections;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics;
using MacDiag.Mcp.Diagnostics.Handles;
using MacDiag.Mcp.Diagnostics.Network;
using MacDiag.Mcp.Diagnostics.Processes;
using MacDiag.Mcp.Mac;

namespace MacDiag.Mcp.Tests;

/// <summary>Each test makes its own evidence on a real Mac and asks a tool to find it; CI's macos-latest job runs them.</summary>
/// <remarks>
/// These are what settle the assumptions the parsers were written on without a Mac: lsof's and ps's escaping in the
/// C locale, socket grouping, and the /private and firmlink spellings.
/// </remarks>
[SupportedOSPlatform("macos")]
public sealed class LiveMacTests : IDisposable
{
    private static readonly MacDiagOptions Options = MacDiagOptions.FromEnvironment(new Hashtable());
    private readonly string _root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"live-{Guid.NewGuid():N}")).FullName;
    private readonly List<Process> _children = [];

    public void Dispose()
    {
        foreach (var child in _children)
        {
            try
            {
                child.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }

            child.Dispose();
        }

        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private static MacSystemCommand Commands => new();

    [MacFact]
    public async Task An_open_file_with_a_non_ascii_name_is_listed_decoded_and_found_under_both_spellings()
    {
        var path = Path.Combine(_root, "café ünïcode.txt");
        await using var held = new FileStream(path, FileMode.Create);
        var handles = new MacHandleInspector(Commands, new MacPrivilegeProbe(), Options);

        var mine = await handles.ForProcessAsync(Environment.ProcessId, includeAllObjectTypes: false, CancellationToken.None);
        Assert.Contains(mine.Entries, e => e.Name.EndsWith("café ünïcode.txt", StringComparison.Ordinal));

        // TMPDIR is /var/folders/...; the kernel reports /private/var/folders/... -- both must find it.
        foreach (var spelling in PathSpellings.Of(path, PathSpellings.SystemFirmlinks).Where(s => !s.StartsWith("/System/Volumes/Data", StringComparison.Ordinal)))
        {
            var found = await handles.SearchAsync(spelling, includeAllObjectTypes: false, CancellationToken.None);
            Assert.Contains(found.Entries, e => e.ProcessId == Environment.ProcessId);
        }
    }

    [MacFact]
    public async Task A_listening_socket_is_owned_by_this_process_and_reads_as_listen()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var result = await new MacNetworkInspector(Commands, Options).EndpointsAsync(port, null, listeningOnly: true, CancellationToken.None);

        var endpoint = Assert.Single(result.Endpoints);
        Assert.Equal("Listen", endpoint.State);
        Assert.Contains(endpoint.Owners, o => o.ProcessId == Environment.ProcessId);
    }

    [MacFact]
    public async Task A_bound_unix_socket_and_a_held_fifo_are_listed_by_name()
    {
        var socketPath = Path.Combine(_root, "live.sock");
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        socket.Bind(new UnixDomainSocketEndPoint(socketPath));
        socket.Listen();

        var fifo = Path.Combine(_root, "live.fifo");
        Process.Start("/usr/bin/mkfifo", [fifo])!.WaitForExit();
        // Opened read-write in a child, which does not block waiting for a writer.
        _children.Add(Process.Start("/bin/sh", ["-c", "exec 3<> \"$0\"; sleep 30", fifo])!);
        await Task.Delay(500);

        var pipes = await new MacPipeInspector(Commands, Options).ListAsync("live", CancellationToken.None);

        Assert.Contains(pipes.Pipes, p => p.Kind == "UnixSocket" && p.Name.EndsWith("live.sock", StringComparison.Ordinal));
        Assert.Contains(pipes.Pipes, p => p.Kind == "Fifo" && p.Name.EndsWith("live.fifo", StringComparison.Ordinal));
    }

    [MacFact]
    public async Task A_command_line_with_spaces_and_non_ascii_comes_back_as_it_was_given()
    {
        var child = Process.Start("/bin/sh", ["-c", "sleep 30", "arg with space café"])!;
        _children.Add(child);
        await Task.Delay(500);

        var table = await new MacProcessTable(Commands, Options).ReadAsync(CancellationToken.None);

        var row = table.Processes.Single(p => p.ProcessId == child.Id);
        Assert.Contains("arg with space café", row.CommandLine, StringComparison.Ordinal);
        Assert.Equal("/bin/sh", row.ExecutablePath);
    }
}
