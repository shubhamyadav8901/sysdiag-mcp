using System.Net.Sockets;
using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Diagnostics.Network;
using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Tools;

namespace LinuxDiag.Mcp.Tests;

public sealed class PipeTests : IDisposable
{
    private static readonly LinuxDiagOptions Options = LinuxDiagOptions.FromEnvironment(new System.Collections.Hashtable());

    private readonly string _root = Directory.CreateDirectory(
        Path.Combine(Path.GetTempPath(), $"ld-pipes-{Guid.NewGuid():N}")).FullName;

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    [Fact]
    public void Unix_socket_lines_give_type_state_listening_inode_and_a_path_with_spaces()
    {
        // The first three lines are captured from WSL Ubuntu's /proc/net/unix.
        var entries = UnixSockets.Parse(
            "Num       RefCount Protocol Flags    Type St Inode Path\n" +
            "0000000000000000: 00000003 00000000 00000000 0001 03 19303\n" +
            "0000000000000000: 00000002 00000000 00010000 0001 01 19159 /run/WSL/2_interop\n" +
            "0000000000000000: 00000002 00000000 00010000 0005 01 11310 /mnt/wslg/weston-notify.sock\n" +
            "0000000000000000: 00000002 00000000 00010000 0002 01 12000 @/tmp/.X11-unix/X0\n" +
            "0000000000000000: 00000002 00000000 00010000 0001 01  8247 /run/my app/control.sock\n");

        Assert.Null(entries[0].Path);
        Assert.Equal(3, entries[0].State);
        Assert.True(entries[1].Listening);
        Assert.Equal(19159, entries[1].Inode);
        Assert.Equal("UnixSeqPacket", UnixSockets.KindName(entries[2].Type));
        Assert.Equal("@/tmp/.X11-unix/X0", entries[3].Path);
        Assert.Equal("/run/my app/control.sock", entries[4].Path);
    }

    [Fact]
    public void Every_captured_distro_parses()
    {
        foreach (var distro in ProcParserTests.Distros())
        {
            var text = ProcParserTests.Fixture(distro, "net-unix")!;
            Assert.Equal(text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length - 1, UnixSockets.Parse(text).Count);
        }
    }

    [Fact]
    public void Listening_names_are_called_out_with_their_holders()
    {
        var summary = PipeTools.RenderPipes(new NamedPipeList(
            [new NamedPipe("/run/app.sock", "UnixStream", true, 2, [new PipeOwner(10, "app")], false, "net:[1]")],
            1, false, []), null);

        Assert.Contains("/run/app.sock (UnixStream, listening, 2 connected) held by app (PID 10)", summary, StringComparison.Ordinal);
    }

    [LinuxFact]
    public void A_unix_listener_and_a_fifo_this_process_holds_are_listed_with_this_process_as_holder()
    {
        var socketPath = Path.Combine(_root, "control.sock");
        var fifoPath = Path.Combine(_root, "events.fifo");
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(socketPath));
        listener.Listen();
        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        client.Connect(new UnixDomainSocketEndPoint(socketPath));
        using var accepted = listener.Accept();
        LockParserTests.Run("mkfifo", fifoPath);
        using var fifo = new FileStream(fifoPath, FileMode.Open, FileAccess.ReadWrite); // O_RDWR: does not block on a FIFO

        var pipes = new LinuxPipeInspector(new LinuxProcessTable(), Options).List(_root, CancellationToken.None);

        var socket = Assert.Single(pipes.Pipes, p => p.Name == socketPath);
        Assert.True(socket.Listening);
        Assert.True(socket.ConnectedCount >= 1);
        Assert.Contains(socket.Owners, o => o.ProcessId == Environment.ProcessId);
        var named = Assert.Single(pipes.Pipes, p => p.Name == fifoPath);
        Assert.Equal("Fifo", named.Kind);
        Assert.Contains(named.Owners, o => o.ProcessId == Environment.ProcessId);
    }
}
