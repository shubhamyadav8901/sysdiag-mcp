using System.Runtime.InteropServices;
using Diag.Mcp.Server.Files;
using Microsoft.Extensions.Logging.Abstractions;

namespace Diag.Mcp.Server.Tests;

/// <summary>
/// A write into the server's own directory is staging a build for <c>update_self</c>, and on a server
/// that says so it needs that grant: on Linux that directory holds a root service's binary.
/// </summary>
/// <remarks>
/// The server directory is passed in rather than taken from the process. Under <c>dotnet test</c> on
/// Linux the process is <c>dotnet</c> itself, so its directory is the SDK's -- not writable, and not
/// something a test should be writing into on any platform.
/// </remarks>
public sealed class ServerDirectoryWriteTests : IDisposable
{
    private const string SelfUpdateSetting = "LINUXDIAG_ALLOW_SELF_UPDATE=1";
    private const string ArbitraryWriteSetting = "LINUXDIAG_ALLOW_ARBITRARY_WRITE=1";

    private readonly string _root;
    private readonly string _serverDir;
    private readonly string _artifactDir;

    public ServerDirectoryWriteTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"diag-serverdir-{Guid.NewGuid():N}");
        _serverDir = Directory.CreateDirectory(Path.Combine(_root, "opt")).FullName;
        _artifactDir = Directory.CreateDirectory(Path.Combine(_root, "artifacts")).FullName;
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    private FileReceiver Receiver(
        bool serverDirectoryWritable, bool allowArbitrary = false, string? serverDirectory = null, string? artifactDirectory = null) =>
        new(new FileTransferOptions(artifactDirectory ?? _artifactDir, allowArbitrary, false,
                ArbitraryWriteSetting, "LINUXDIAG_ALLOW_ARBITRARY_READ=1",
                serverDirectoryWritable, SelfUpdateSetting),
            NullLogger<FileReceiver>.Instance,
            serverDirectory ?? _serverDir);

    private static FileWriteRequest Put(string path) => new(path, [1, 2, 3]);

    [Fact]
    public void Refuses_a_write_into_the_server_directory_without_the_self_update_grant_and_names_it()
    {
        var target = Path.Combine(_serverDir, "LinuxDiag.Mcp.new");

        var ex = Assert.Throws<FileTransferException>(
            () => Receiver(serverDirectoryWritable: false).Receive(Put(target), CancellationToken.None));

        Assert.Contains(SelfUpdateSetting, ex.Message, StringComparison.Ordinal);
        Assert.Contains(ArbitraryWriteSetting, ex.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(target));
    }

    [Fact]
    public void Refuses_an_append_into_the_server_directory_without_the_grant()
    {
        // Every chunk after the first is an append. The gate must sit in front of that path too, or a
        // chunked send would be refused its first chunk and still be able to grow a file there.
        var target = Path.Combine(_serverDir, "LinuxDiag.Mcp.new");

        Assert.Throws<FileTransferException>(() => Receiver(serverDirectoryWritable: false).Receive(
            new FileWriteRequest(target, [1], Append: true), CancellationToken.None));

        Assert.False(File.Exists(target));
    }

    [Fact]
    public void Allows_a_write_into_the_server_directory_with_the_self_update_grant()
    {
        var target = Path.Combine(_serverDir, "LinuxDiag.Mcp.new");

        var result = Receiver(serverDirectoryWritable: true).Receive(Put(target), CancellationToken.None);

        Assert.Equal(WriteScope.WinDiag, result.Scope);
        Assert.True(File.Exists(target));
    }

    [Fact]
    public void Allows_a_write_into_the_server_directory_with_arbitrary_write()
    {
        var target = Path.Combine(_serverDir, "LinuxDiag.Mcp.new");

        Receiver(serverDirectoryWritable: false, allowArbitrary: true).Receive(Put(target), CancellationToken.None);

        Assert.True(File.Exists(target));
    }

    [Fact]
    public void Still_writes_freely_into_the_artifact_directory_without_the_grant()
    {
        var target = Path.Combine(_artifactDir, "input.bin");

        Receiver(serverDirectoryWritable: false).Receive(Put(target), CancellationToken.None);

        Assert.True(File.Exists(target));
    }

    [Fact]
    public void An_artifact_directory_inside_the_server_directory_stays_writable_without_the_grant()
    {
        // The artifact directory is owned in its own right; that an operator nested it under the
        // server's folder does not make an input dropped there a build being staged.
        var nested = Directory.CreateDirectory(Path.Combine(_serverDir, "artifacts")).FullName;
        var target = Path.Combine(nested, "input.bin");

        Receiver(serverDirectoryWritable: false, artifactDirectory: nested).Receive(Put(target), CancellationToken.None);

        Assert.True(File.Exists(target));
    }

    [UnixFact]
    public void A_link_in_the_artifact_directory_into_the_server_directory_is_refused_without_the_grant()
    {
        // Judged where the write really lands: a link planted among the artifacts must not carry a
        // write into the server's folder while the path still looks like an artifact.
        Directory.CreateSymbolicLink(Path.Combine(_artifactDir, "bin"), _serverDir);

        Assert.Throws<FileTransferException>(() => Receiver(serverDirectoryWritable: false).Receive(
            Put(Path.Combine(_artifactDir, "bin", "LinuxDiag.Mcp.new")), CancellationToken.None));

        Assert.False(File.Exists(Path.Combine(_serverDir, "LinuxDiag.Mcp.new")));
    }

    [UnixFact]
    public void A_server_directory_reached_through_a_link_is_judged_by_its_real_path()
    {
        // The other direction: the server runs from a linked path (/opt/current -> /opt/linuxdiag-2.1),
        // and the write names the real directory. Compared as spelled, the two would not match, the path
        // would look foreign, and the refusal would name arbitrary write -- the wrong grant to ask for.
        var linked = Path.Combine(_root, "current");
        Directory.CreateSymbolicLink(linked, _serverDir);

        var ex = Assert.Throws<FileTransferException>(() => Receiver(serverDirectoryWritable: false, serverDirectory: linked)
            .Receive(Put(Path.Combine(_serverDir, "LinuxDiag.Mcp.new")), CancellationToken.None));

        Assert.Contains(SelfUpdateSetting, ex.Message, StringComparison.Ordinal);
    }

    [UnixFact]
    public void A_linked_server_directory_is_writable_through_its_real_path_with_the_grant()
    {
        var linked = Path.Combine(_root, "current");
        Directory.CreateSymbolicLink(linked, _serverDir);

        Receiver(serverDirectoryWritable: true, serverDirectory: linked)
            .Receive(Put(Path.Combine(_serverDir, "LinuxDiag.Mcp.new")), CancellationToken.None);

        Assert.True(File.Exists(Path.Combine(_serverDir, "LinuxDiag.Mcp.new")));
    }

    [Fact]
    public void The_kit_loads_the_c_library_through_its_system_name_resolver()
    {
        var checkedImports = NativeImportGuard.AssertEveryImportUsesTheSystemResolver(typeof(FileReceiver).Assembly);

        Assert.True(checkedImports > 0, "The sweep found no P/Invoke in the kit; it would pass vacuously.");
    }

    [Fact]
    public void The_resolver_answers_only_for_the_c_library()
    {
        Assert.Equal(IntPtr.Zero, SystemLibrary.Resolve("libssl", typeof(FileReceiver).Assembly, null));
    }

    [LinuxFact]
    public void The_resolver_loads_the_c_library_by_its_system_name()
    {
        Assert.Equal(
            NativeLibrary.Load(SystemLibrary.CLibrary),
            SystemLibrary.Resolve("libc", typeof(FileReceiver).Assembly, null));
    }
}
