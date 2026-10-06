using System.Runtime.InteropServices;
using System.Text;
using Diag.Mcp.Server.Files;
using Microsoft.Extensions.Logging.Abstractions;

namespace Diag.Mcp.Server.Tests;

/// <summary>
/// One Windows directory has more than one spelling, and the self-update gate must see through all of them.
/// </summary>
/// <remarks>
/// <para>The gate compares spellings, and "not in the server directory" is its permissive answer. With the
/// artifact directory above the server's -- <c>C:\Diag</c> holding <c>C:\Diag\WinDiag Server</c> -- a path
/// spelled through the 8.3 name <c>C:\Diag\WINDIA~1\crypt32.dll</c> was owned through the artifact
/// directory, never gated, and written beside a SYSTEM service whose runtime loads its imports from that
/// folder at the next start.</para>
/// <para>The fake-driven facts run everywhere, so the walk's rules are pinned on any machine; the
/// Windows facts put a real short name, a real device prefix and a real stream through the same gate.</para>
/// </remarks>
public sealed class WindowsSpellingTests
{
    // Never touched on disk by the fake-driven facts.
    private static readonly string Artifacts = Path.Combine(Path.GetTempPath(), "spelling-fake-diag");
    private static readonly string Server = Path.Combine(Artifacts, "WinDiag Server");
    private static readonly string ShortServer = Path.Combine(Artifacts, "WINDIA~1");

    private static string? NoLinks(string path) => null;

    /// <summary>What GetLongPathNameW answers for this fake volume: the one short name, spelled out.</summary>
    private static string FakeLongName(string path) => path == ShortServer ? Server : path;

    private static (string, bool) FakeWindowsWalk(string path) =>
        PathScope.Walk(path, NoLinks, windowsTargets: true, isMagicLink: null, FakeLongName);

    private static FileTransferOptions ArtifactsAbove(string artifacts) =>
        new(artifacts, false, false, "WINDIAG_ALLOW_ARBITRARY_WRITE=1", "WINDIAG_ALLOW_ARBITRARY_READ=1",
            ServerDirectoryWritable: false, ServerDirectorySetting: "WINDIAG_ALLOW_SELF_UPDATE=1");

    [Fact]
    public void A_short_name_spelling_of_the_server_directory_is_still_in_it()
    {
        var (scope, inServer) = FileScope.Classify(
            Path.Combine(ShortServer, "crypt32.dll"), ArtifactsAbove(Artifacts), Server, replacesFinalLink: false,
            looseServerMatch: false, isNetworkOrDevice: _ => false, walk: FakeWindowsWalk);

        Assert.Equal(WriteScope.Owned, scope);
        Assert.True(inServer, "an 8.3 spelling of the server directory skipped the self-update gate");
    }

    [Fact]
    public void A_server_directory_configured_by_its_short_name_still_contains_the_long_spelling()
    {
        // The same second spelling from the other side: a service whose image path was registered as
        // C:\PROGRA~1\... has a process directory spelled short, and every long-spelled request missed it.
        var (_, inServer) = FileScope.Classify(
            Path.Combine(Server, "crypt32.dll"), ArtifactsAbove(Artifacts), ShortServer, replacesFinalLink: false,
            looseServerMatch: false, isNetworkOrDevice: _ => false, walk: FakeWindowsWalk);

        Assert.True(inServer);
    }

    [Fact]
    public void A_component_that_does_not_exist_yet_keeps_its_spelling()
    {
        // The file about to be written has no short form, so the walk must not ask for one past the
        // last component that exists -- and must keep the name the caller gave.
        var asked = new List<string>();
        string LongName(string path)
        {
            asked.Add(path);
            return path;
        }

        var (real, _) = PathScope.Walk(
            Path.Combine(Server, "new.bin"), NoLinks, windowsTargets: true, isMagicLink: null, LongName);

        Assert.Equal(Path.Combine(Server, "new.bin"), real);
        Assert.Contains(Server, asked);
    }

    [Fact]
    public void A_stream_suffix_on_a_directory_on_the_way_is_refused_under_the_windows_rule()
    {
        // dir::$INDEX_ALLOCATION opens the directory itself, so this is the server folder spelled so that it
        // does not start with the server folder's name.
        var path = Path.Combine(Artifacts, "WinDiag Server::$INDEX_ALLOCATION", "crypt32.dll");

        var ex = Assert.Throws<FileTransferException>(() =>
            PathScope.Walk(path, NoLinks, windowsTargets: true, isMagicLink: null, FakeLongName));

        Assert.Contains("stream", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_colon_in_a_directory_name_is_left_alone_under_the_posix_rule()
    {
        // ':' is an ordinary character in a Linux or macOS name; the stream rule is Windows' alone.
        var path = Path.Combine(Artifacts, "a:b", "x");

        var (real, _) = PathScope.Walk(path, NoLinks, windowsTargets: false, isMagicLink: null);

        Assert.Equal(path, real);
    }

    [Fact]
    public void A_stream_on_the_file_itself_is_not_a_directory_spelling_and_is_judged_where_it_sits()
    {
        // x.dll:s is a stream of a file in the directory the path names, so nothing is misjudged by it.
        var path = Path.Combine(Server, "x.dll:s");

        var (real, _) = PathScope.Walk(path, NoLinks, windowsTargets: true, isMagicLink: null, FakeLongName);

        Assert.Equal(path, real);
    }

    [Theory]
    [InlineData(@"\\?\C:\", @"C:\")]
    [InlineData(@"\\.\D:\", @"D:\")]
    [InlineData(@"\??\C:\", @"C:\")]
    [InlineData(@"//?/C:/", "C:/")]
    [InlineData(@"C:\", @"C:\")]
    [InlineData(@"\\server\share\", @"\\server\share\")]
    [InlineData(@"\\?\Volume{11111111-1111-1111-1111-111111111111}\", @"\\?\Volume{11111111-1111-1111-1111-111111111111}\")]
    public void A_device_prefixed_drive_root_is_judged_as_the_drive_letter_root(string root, string expected)
    {
        Assert.Equal(expected, PathScope.DriveLetterRoot(root));
    }

    [WindowsFact]
    public void The_long_path_prefix_spelling_of_the_server_directory_is_in_it()
    {
        using var layout = new RealLayout();

        var (_, inServer) = FileScope.Classify(
            @"\\?\" + Path.Combine(layout.Server, "crypt32.dll"), ArtifactsAbove(layout.Artifacts), layout.Server);

        Assert.True(inServer);
    }

    [WindowsFact]
    public void A_real_stream_spelling_of_the_server_directory_is_refused()
    {
        using var layout = new RealLayout();

        Assert.Throws<FileTransferException>(() => FileScope.Classify(
            Path.Combine(layout.Server + "::$INDEX_ALLOCATION", "crypt32.dll"), ArtifactsAbove(layout.Artifacts), layout.Server));
    }

    [WindowsShortNameFact]
    public void A_real_short_name_spelling_of_the_server_directory_is_gated_and_nothing_is_written()
    {
        using var layout = new RealLayout();
        var shortServer = WindowsShortNameFactAttribute.ShortName(layout.Server);
        Assert.NotEqual(layout.Server, shortServer, StringComparer.OrdinalIgnoreCase);
        var planted = Path.Combine(shortServer, "crypt32.dll");

        var receiver = new FileReceiver(ArtifactsAbove(layout.Artifacts), NullLogger<FileReceiver>.Instance, layout.Server);
        var ex = Assert.Throws<FileTransferException>(
            () => receiver.Receive(new FileWriteRequest(planted, [1, 2, 3]), CancellationToken.None));

        Assert.Contains("WINDIAG_ALLOW_SELF_UPDATE=1", ex.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(layout.Server, "crypt32.dll")));
    }

    /// <summary>An artifact directory with the server's directory, named with a space so NTFS gives it a short name, inside.</summary>
    private sealed class RealLayout : IDisposable
    {
        public RealLayout()
        {
            Artifacts = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"spelling-{Guid.NewGuid():N}")).FullName;
            Server = Directory.CreateDirectory(Path.Combine(Artifacts, "WinDiag Server Folder")).FullName;
        }

        public string Artifacts { get; }

        public string Server { get; }

        public void Dispose()
        {
            try { Directory.Delete(Artifacts, recursive: true); } catch (IOException) { }
        }
    }
}

/// <summary>A Windows fact that needs NTFS to generate 8.3 short names, and reports itself skipped where it does not.</summary>
/// <remarks>
/// Short-name generation is a per-volume setting (<c>fsutil 8dot3name</c>), off on many data volumes and
/// some images. Probed by creating a long-named directory and asking for its short name, not inferred
/// from the setting: the probe is the answer that cannot be wrong.
/// </remarks>
public sealed class WindowsShortNameFactAttribute : FactAttribute
{
    private static readonly Lazy<bool> Generated = new(Probe);

    public WindowsShortNameFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Windows only.";
        }
        else if (!Generated.Value)
        {
            Skip = "The temp directory's volume does not generate 8.3 short names.";
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetShortPathNameW(string longPath, StringBuilder shortPath, uint bufferLength);

    /// <summary>The 8.3 spelling Windows reports for an existing path, or the path itself when it has none.</summary>
    public static string ShortName(string path)
    {
        var buffer = new StringBuilder(1024);
        var length = GetShortPathNameW(path, buffer, (uint)buffer.Capacity);
        return length is > 0 and < 1024 ? buffer.ToString() : path;
    }

    private static bool Probe()
    {
        var probe = Path.Combine(Path.GetTempPath(), $"short name probe {Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(probe);
            return !string.Equals(Path.GetFileName(ShortName(probe)), Path.GetFileName(probe), StringComparison.OrdinalIgnoreCase);
        }
        catch (IOException)
        {
            return false;
        }
        finally
        {
            try { Directory.Delete(probe); } catch (IOException) { }
        }
    }
}
