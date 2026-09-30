using System.IO.MemoryMappedFiles;
using System.Net;
using System.Net.Sockets;
using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Diagnostics;
using LinuxDiag.Mcp.Diagnostics.Handles;
using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Tools;

namespace LinuxDiag.Mcp.Tests;

public sealed class OpenFileTests : IDisposable
{
    private readonly string _root = Directory.CreateDirectory(
        Path.Combine(Path.GetTempPath(), $"ld-open-{Guid.NewGuid():N}")).FullName;

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    private static readonly LinuxDiagOptions Options = LinuxDiagOptions.FromEnvironment(new System.Collections.Hashtable());

    private static HandleEntry Entry(int pid, string name) =>
        new("worker", pid, "File", "root", 0, "3", name, "read", false);

    [Fact]
    public void Modules_filter_by_path_count_deleted_ones_and_cap_rows()
    {
        var files = new List<MappedFile>
        {
            new("/usr/bin/nginx", 0x1000, 4096, true, false, false),
            new("/usr/lib/libssl.so.3", 0x2000, 4096, true, false, true),
            new("/usr/lib/libc.so.6", 0x3000, 4096, true, false, false),
        };

        var all = LinuxModuleInspector.Build(10, "nginx", files, null, 2);
        var ssl = LinuxModuleInspector.Build(10, "nginx", files, "ssl", 100);

        Assert.Equal(2, all.Modules.Count);
        Assert.True(all.Truncated);
        Assert.Equal(3, all.TotalMatched);
        Assert.Equal("libssl.so.3", Assert.Single(ssl.Modules).Name);
        Assert.Equal(1, ssl.DeletedCount);
        Assert.Equal("0x2000", ssl.Modules[0].BaseAddress);
        Assert.Contains("restart it", ModuleTools.Render(ssl, "ssl"), StringComparison.Ordinal);
    }

    [Fact]
    public void A_non_root_handle_list_warns_that_it_is_partial()
    {
        // Review Focus 2.
        var summary = HandleTools.RenderHandleSummary(
            new HandleSearch("PID 10", [Entry(10, "/var/log/app.log")], false, false, 1, 4, true, true));

        Assert.StartsWith("WARNING: the server is not running as root", summary, StringComparison.Ordinal);
        Assert.Contains("4 processes could not be read", summary, StringComparison.Ordinal);
        Assert.Contains("/var/log/app.log", summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Five_hundred_handles_render_two_hundred_and_say_so()
    {
        // Review Focus 5.
        var entries = Enumerable.Range(1, 500).Select(i => Entry(i, "/tmp/f" + i)).ToList();

        var summary = HandleTools.RenderHandleSummary(new HandleSearch("f", entries, true, false, 500, 0, false, false));

        Assert.Contains("Summary lists the first 200 of 500", summary, StringComparison.Ordinal);
        Assert.DoesNotContain("/tmp/f201", summary, StringComparison.Ordinal);
    }

    [LinuxFact]
    public void Process_handles_lists_a_file_written_and_a_listening_socket_with_how_each_was_opened()
    {
        var path = Path.Combine(_root, "held.log");
        using var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var search = new LinuxHandleInspector(new LinuxProcessTable(), new LinuxPrivilegeProbe(), Options)
            .ForProcess(Environment.ProcessId, includeAllObjectTypes: true, CancellationToken.None);

        var held = Assert.Single(search.Entries, e => e.Name == path);
        Assert.Equal("File", held.Type);
        Assert.Equal("write", held.Access);
        Assert.Contains(search.Entries, e => e.Type == "Socket");
        Assert.Contains(search.Entries, e => e.Type == "Mapped" && e.Name.Contains("libcoreclr", StringComparison.Ordinal));
        Assert.True(search.ProcessScoped);
    }

    [LinuxFact]
    public void File_references_only_leaves_sockets_out()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var search = new LinuxHandleInspector(new LinuxProcessTable(), new LinuxPrivilegeProbe(), Options)
            .ForProcess(Environment.ProcessId, includeAllObjectTypes: false, CancellationToken.None);

        Assert.DoesNotContain(search.Entries, e => e.Type is "Socket" or "Pipe" or "AnonInode");
    }

    [LinuxFact]
    public void A_mapped_file_deleted_from_disk_is_flagged_as_stale()
    {
        var path = Path.Combine(_root, "mapped.bin");
        File.WriteAllBytes(path, new byte[8192]);
        using var mapping = MemoryMappedFile.CreateFromFile(path, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
        using var view = mapping.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
        File.Delete(path);

        var modules = new LinuxModuleInspector(Options).Read(Environment.ProcessId, "mapped.bin");

        var module = Assert.Single(modules.Modules);
        Assert.True(module.Deleted);
        Assert.Equal(path, module.Path);
    }

    [LinuxFact]
    public void A_pid_that_is_not_running_is_a_readable_refusal_from_both_tools()
    {
        var handles = Assert.Throws<HandleQueryException>(() =>
            new LinuxHandleInspector(new LinuxProcessTable(), new LinuxPrivilegeProbe(), Options)
                .ForProcess(int.MaxValue, true, CancellationToken.None));
        var modules = Assert.Throws<ModuleQueryException>(() => new LinuxModuleInspector(Options).Read(int.MaxValue, null));

        Assert.Contains("No process with PID", handles.Message, StringComparison.Ordinal);
        Assert.Contains("No process with PID", modules.Message, StringComparison.Ordinal);
    }
}
