using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.External;
using WinDiag.Mcp.Diagnostics.Handles;
using WinDiag.Mcp.Diagnostics.Locks;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

public sealed class FileLockToolsTests
{
    private static FileLockTools Build(
        LockQueryResult? locks = null,
        HandleSearchResult? handles = null,
        bool elevated = true)
    {
        return new FileLockTools(
            new FakeLockInspector(locks ?? new LockQueryResult("x", [], Exhaustive: false)),
            new FakeHandleInspector(handles ?? new HandleSearchResult("x", [], elevated, false, 0, false)),
            new FakePrivilegeProbe(elevated));
    }

    private static LockHolder Holder(int pid = 1234, string name = "WINWORD.EXE", bool running = true) =>
        new(pid, name, "Microsoft Word", null, LockHolderKind.MainWindow, DateTimeOffset.UnixEpoch, running);

    [Fact]
    public async Task Empty_lock_result_never_reads_as_a_definitive_no()
    {
        // The most important behaviour in the tool. Restart Manager misses services, kernel-held
        // references and mapped sections, so a bare "no holders" would end an investigation that
        // should have continued into the exhaustive search.
        var tools = Build();
        var temp = Path.GetTempFileName();

        try
        {
            var result = tools.WhoLocksPath(temp, CancellationToken.None);

            Assert.Empty(result.Holders);
            Assert.False(result.Exhaustive);
            Assert.Contains("NOT proof", result.Summary);
            Assert.Contains("path_handle_search", result.Summary);
        }
        finally
        {
            File.Delete(temp);
        }

        await Task.CompletedTask;
    }

    [Fact]
    public void Empty_lock_result_calls_out_a_path_that_does_not_exist()
    {
        var tools = Build();
        var missing = Path.Combine(Path.GetTempPath(), $"windiag-missing-{Guid.NewGuid():N}.tmp");

        var result = tools.WhoLocksPath(missing, CancellationToken.None);

        Assert.Contains("does not currently exist", result.Summary);
    }

    [Fact]
    public void Holders_are_listed_and_the_coverage_caveat_still_appears()
    {
        var tools = Build(new LockQueryResult("x", [Holder()], Exhaustive: false));

        var result = tools.WhoLocksPath(Path.GetTempPath(), CancellationToken.None);

        Assert.Contains("WINWORD.EXE", result.Summary);
        Assert.Contains("1234", result.Summary);
        Assert.Contains("Microsoft Word", result.Summary);

        // Finding something does not make the answer complete.
        Assert.Contains("not exhaustive", result.Summary);
    }

    [Fact]
    public void A_holder_whose_pid_was_recycled_is_flagged_as_unsafe_to_act_on()
    {
        var tools = Build(new LockQueryResult("x", [Holder(running: false)], Exhaustive: false));

        var result = tools.WhoLocksPath(Path.GetTempPath(), CancellationToken.None);

        Assert.Contains("do not act on this PID", result.Summary);
    }

    [Fact]
    public async Task Unelevated_handle_search_leads_with_the_partial_results_warning()
    {
        // Unelevated, handle.exe returns a shorter list rather than an error, so a missing entry is
        // indistinguishable from an absent handle unless the caller is told.
        var entries = new[] { new HandleEntry("explorer.exe", 3628, "File", @"CONTOSO\u", "0x1", @"C:\x") };
        var tools = Build(
            handles: new HandleSearchResult("x", entries, Elevated: false, false, 1, false),
            elevated: false);

        var result = await tools.PathHandleSearch("x");

        Assert.StartsWith("WARNING", result.Summary);
        Assert.Contains("partial", result.Summary);
        Assert.False(result.Elevated);
    }

    [Fact]
    public async Task Elevated_handle_search_reports_results_without_a_warning()
    {
        var entries = new[] { new HandleEntry("explorer.exe", 3628, "File", @"CONTOSO\u", "0x1", @"C:\x") };
        var tools = Build(
            handles: new HandleSearchResult("x", entries, Elevated: true, false, 1, false),
            elevated: true);

        var result = await tools.PathHandleSearch("x");

        Assert.DoesNotContain("WARNING", result.Summary);
        Assert.Contains("explorer.exe", result.Summary);
    }

    [Fact]
    public async Task Truncated_handle_search_says_how_much_was_withheld()
    {
        var entries = new[] { new HandleEntry("a.exe", 1, "File", null, "0x1", @"C:\x") };
        var tools = Build(handles: new HandleSearchResult(
            "x", entries, true, Truncated: true, TotalMatched: 500, IncludedAllObjectTypes: false));

        var result = await tools.PathHandleSearch("x");

        // Silent truncation reads as "that is all there is".
        Assert.Contains("500", result.Summary);
        Assert.Contains("WINDIAG_MAX_RESULTS", result.Summary);
    }

    private const string SampleCsv =
        "Process,PID,User,Handle,Type,Share Flags,Name,Access\r\napp.exe,7,File,CONTOSO\\u,0x9,C:\\t\r\n";

    [Fact]
    public async Task File_only_search_omits_the_expensive_all_types_flag()
    {
        var runner = new StubExternalToolRunner(SampleCsv);
        var inspector = new HandleExeInspector(runner, new FakePrivilegeProbe(true), new WinDiagOptions());

        await inspector.SearchAsync("Fonts", includeAllObjectTypes: false, CancellationToken.None);

        var (executable, argv) = Assert.Single(runner.Invocations);
        Assert.Equal("handle.exe", executable);
        Assert.Equal(["-accepteula", "-nobanner", "-u", "-v", "Fonts"], argv);
    }

    [Fact]
    public async Task All_types_search_adds_the_flag_that_reaches_registry_keys()
    {
        // Without -a, handle.exe dumps file references only -- no registry keys, whatever the tool
        // description promises. It is opt-in because a machine-wide -a search had produced 223 rows,
        // all still Files, after 6m40s.
        var runner = new StubExternalToolRunner(SampleCsv);
        var inspector = new HandleExeInspector(runner, new FakePrivilegeProbe(true), new WinDiagOptions());

        await inspector.SearchAsync("CurrentVersion", includeAllObjectTypes: true, CancellationToken.None);

        var (_, argv) = Assert.Single(runner.Invocations);
        Assert.Equal(["-accepteula", "-nobanner", "-a", "-u", "-v", "CurrentVersion"], argv);
    }

    [Fact]
    public async Task An_empty_file_only_result_says_it_did_not_look_at_other_object_types()
    {
        // "No handles matched" over a file-only search would send the caller away from a registry key
        // that is sitting right there, unexamined.
        var tools = Build(handles: new HandleSearchResult("x", [], true, false, 0, IncludedAllObjectTypes: false));

        var result = await tools.PathHandleSearch("x");

        Assert.Contains("FILE handles only", result.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("includeAllObjectTypes=true", result.Summary);
    }

    [Fact]
    public async Task An_empty_all_types_result_is_reported_as_genuinely_empty()
    {
        var tools = Build(handles: new HandleSearchResult("x", [], true, false, 0, IncludedAllObjectTypes: true));

        var result = await tools.PathHandleSearch("x", includeAllObjectTypes: true);

        Assert.Contains("any object type", result.Summary);
        Assert.DoesNotContain("includeAllObjectTypes=true", result.Summary);
    }

    [Fact]
    public async Task A_search_term_shaped_like_a_switch_is_refused_before_the_process_starts()
    {
        // handle.exe -c closes a handle and can destabilise the machine. This must never be reachable
        // from a caller-supplied value.
        var runner = new StubExternalToolRunner();
        var inspector = new HandleExeInspector(runner, new FakePrivilegeProbe(true), new WinDiagOptions());

        await Assert.ThrowsAsync<UnsafeArgumentException>(
            () => inspector.SearchAsync("-c", includeAllObjectTypes: false, CancellationToken.None));

        Assert.Empty(runner.Invocations);
    }
}
