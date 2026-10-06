using Diag.Mcp.Server.Files;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.Activity;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

/// <summary>query_activity reads only what get_file may read, and never echoes a file it could not parse.</summary>
/// <remarks>
/// The tool is registered on a read-only server and read any path the server could open, as SYSTEM: a
/// one-line secret -- a .git-credentials file, a connection string -- came back verbatim in the "Columns
/// present" of the parse error, a file shaped like a Procmon export came back row by row, and "does not
/// exist" answered for any path on the machine. README's <c>-Grants None</c> promises such a server
/// cannot read a single config file.
/// </remarks>
public sealed class ActivityQueryScopeTests : IDisposable
{
    private const string Secret = "https://svc:hunter2-not-a-column@git.example.com";

    private readonly string _artifacts = Directory.CreateTempSubdirectory("windiag-activity-owned").FullName;
    private readonly string _outside = Directory.CreateTempSubdirectory("windiag-activity-outside").FullName;

    public void Dispose()
    {
        Directory.Delete(_artifacts, recursive: true);
        Directory.Delete(_outside, recursive: true);
    }

    private sealed class RecordingActivity : IActivityInspector
    {
        public List<string> Asked { get; } = [];

        public Task<ActivityCapture> CaptureAsync(int durationSeconds, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Not used.");

        public ActivityQueryResult Query(string capturePath, ActivityFilter filter, CancellationToken cancellationToken)
        {
            Asked.Add(capturePath);
            return new ActivityQueryResult(capturePath, 0, 0, false, [], [], [], []);
        }
    }

    private ActivityQueryTools Tools(RecordingActivity activity, bool arbitraryRead = false) =>
        new(activity, new WinDiagOptions(), new FileTransferOptions(
            _artifacts, false, arbitraryRead, "WINDIAG_ALLOW_ARBITRARY_WRITE=1", "WINDIAG_ALLOW_ARBITRARY_READ=1"));

    private string WriteSecret(string directory)
    {
        var path = Path.Combine(directory, ".git-credentials");
        File.WriteAllText(path, Secret + "\n");
        return path;
    }

    [Fact]
    public void A_capture_path_outside_the_owned_directories_is_refused_before_it_is_opened()
    {
        var activity = new RecordingActivity();

        var ex = Assert.Throws<FileTransferException>(() => Tools(activity).QueryActivity(WriteSecret(_outside)));

        Assert.Contains("WINDIAG_ALLOW_ARBITRARY_READ=1", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", ex.Message, StringComparison.Ordinal);
        Assert.Empty(activity.Asked);
    }

    [Fact]
    public void An_outside_path_that_does_not_exist_gets_the_same_refusal_as_one_that_does()
    {
        // "does not exist" for one and a scope refusal for the other would answer, for any path on the
        // machine, whether it exists.
        var present = Path.Combine(_outside, "here.csv");
        var absent = Path.Combine(_outside, "nowhere.csv");
        File.WriteAllText(present, "x");

        var a = Assert.Throws<FileTransferException>(() => Tools(new RecordingActivity()).QueryActivity(present));
        var b = Assert.Throws<FileTransferException>(() => Tools(new RecordingActivity()).QueryActivity(absent));

        Assert.Equal(a.Message.Replace(present, "<p>"), b.Message.Replace(absent, "<p>"));
    }

    [Fact]
    public void A_capture_in_the_artifact_directory_is_queried_by_its_full_path()
    {
        var activity = new RecordingActivity();
        var capture = Path.Combine(_artifacts, "activity.csv");
        File.WriteAllText(capture, "x");

        Tools(activity).QueryActivity(capture);

        Assert.Equal([capture], activity.Asked);
    }

    [Fact]
    public void Arbitrary_read_lets_a_capture_be_queried_from_anywhere()
    {
        var activity = new RecordingActivity();
        var capture = Path.Combine(_outside, "copied-here.csv");
        File.WriteAllText(capture, "x");

        Tools(activity, arbitraryRead: true).QueryActivity(capture);

        Assert.Equal([capture], activity.Asked);
    }

    [Fact]
    public void A_file_that_is_not_a_capture_is_refused_without_echoing_its_first_line()
    {
        // Reached with the arbitrary-read grant, or for a file someone put in the artifact directory: the
        // error names the columns that are missing, never the cells that are there.
        using var reader = new StringReader(Secret + "\n");

        var ex = Assert.Throws<FormatException>(() => ProcmonCsvReader.Read(reader, CancellationToken.None).ToList());

        Assert.Contains("Process Name", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", ex.Message, StringComparison.Ordinal);
    }
}
