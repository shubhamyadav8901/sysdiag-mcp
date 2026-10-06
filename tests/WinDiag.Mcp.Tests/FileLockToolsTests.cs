using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics;
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
            new FakePrivilegeProbe(elevated),
            new Diag.Mcp.Server.Files.FileTransferOptions(
                Path.GetTempPath(), false, false, "WINDIAG_ALLOW_ARBITRARY_WRITE=1", "WINDIAG_ALLOW_ARBITRARY_READ=1"));
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

    /// <summary>A machine with the complete Handle download staged, which is what deploy-target.ps1 leaves.</summary>
    private static FakeToolLocator Locator() => new("handle.exe", "handle64.exe");

    /// <summary>The build that must be chosen on the machine this suite is running on.</summary>
    private static string ExpectedHandleBuild =>
        Environment.Is64BitOperatingSystem ? "handle64.exe" : "handle.exe";

    [Fact]
    public async Task File_only_search_omits_the_expensive_all_types_flag()
    {
        var runner = new StubExternalToolRunner(SampleCsv);
        var inspector = new HandleExeInspector(
            runner, Locator(), new FakePrivilegeProbe(true), new WinDiagOptions());

        await inspector.SearchAsync("Fonts", includeAllObjectTypes: false, CancellationToken.None);

        var (executable, argv) = Assert.Single(runner.Invocations);
        Assert.Equal(ExpectedHandleBuild, executable);
        Assert.Equal(["-accepteula", "-nobanner", "-u", "-v", "Fonts"], argv);
    }

    [Fact]
    public async Task Prefers_the_sixty_four_bit_build_where_the_thirty_two_bit_one_would_find_nothing()
    {
        // Measured, both unelevated on the same x64 box, same filter:
        //   handle.exe   -u -v System32  ->  "No matching handles found."
        //   handle64.exe -u -v System32  ->  526 rows
        // The 32-bit build does not fail, it answers wrongly -- and an empty handle search reads as
        // "nothing holds this file", which is the conclusion that ends an investigation.
        var runner = new StubExternalToolRunner(SampleCsv);
        var locator = Locator();
        var inspector = new HandleExeInspector(
            runner, locator, new FakePrivilegeProbe(true), new WinDiagOptions());

        await inspector.SearchAsync("Fonts", includeAllObjectTypes: false, CancellationToken.None);

        if (Environment.Is64BitOperatingSystem)
        {
            Assert.Equal("handle64.exe", Assert.Single(runner.Invocations).Executable);
            Assert.Contains("handle64.exe", locator.Requested);
        }
        else
        {
            // On 32-bit Windows there is no 64-bit build to want, and asking for one would be noise.
            Assert.Equal("handle.exe", Assert.Single(runner.Invocations).Executable);
            Assert.DoesNotContain("handle64.exe", locator.Requested);
        }
    }

    [Fact]
    public async Task Refuses_a_thirty_two_bit_handle_on_sixty_four_bit_windows()
    {
        if (!Environment.Is64BitOperatingSystem)
        {
            return; // Nothing to refuse: the 32-bit build is the right one here.
        }

        // Only the 32-bit build staged. Refusing beats running it, because running it returns an empty
        // result that is indistinguishable from a genuine "nothing holds this path".
        var runner = new StubExternalToolRunner(SampleCsv);
        var thirtyTwoBit = new FixedArchitectureLocator(PeImageHeader.MachineI386);
        var inspector = new HandleExeInspector(
            runner, thirtyTwoBit, new FakePrivilegeProbe(true), new WinDiagOptions());

        var ex = await Assert.ThrowsAsync<ToolArchitectureException>(
            () => inspector.SearchAsync("Fonts", includeAllObjectTypes: false, CancellationToken.None));

        Assert.Contains("handle64.exe", ex.Message);
        Assert.Contains("No matching handles found", ex.Message);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task All_types_search_adds_the_flag_that_reaches_registry_keys()
    {
        // Without -a, handle.exe dumps file references only -- no registry keys, whatever the tool
        // description promises. It is opt-in because a machine-wide -a search had produced 223 rows,
        // all still Files, after 6m40s.
        var runner = new StubExternalToolRunner(SampleCsv);
        var inspector = new HandleExeInspector(
            runner, Locator(), new FakePrivilegeProbe(true), new WinDiagOptions());

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

        Assert.Contains("file references", result.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("includeAllObjectTypes=true", result.Summary);

        // And it must NOT offer sections as a reason to re-run with -a. Without -a handle.exe returns
        // file REFERENCES, which is broader than File handles: a machine-wide search measured 172 File
        // rows and 112 Section rows, because a section backing a file is a reference to it. Promising
        // sections behind the flag sends someone into a 6m40s -a sweep for rows they already had -- and
        // worse, implies the fast search cannot see a memory-mapped holder, which is the one holder
        // who_locks_path is documented as missing.
        Assert.DoesNotContain("sections or other objects", result.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("mapped sections", result.Summary, StringComparison.OrdinalIgnoreCase);
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
    public async Task Listing_one_process_scopes_by_pid_and_covers_every_object_type()
    {
        // -a is on by default here where it is opt-in for the machine-wide search, because scoped to
        // one process it costs almost nothing -- and the objects it adds, mutants and sections and
        // registry keys, are most of the reason to ask about a single process at all.
        var runner = new StubExternalToolRunner(SampleCsv);
        var inspector = new HandleExeInspector(
            runner, Locator(), new FakePrivilegeProbe(true), new WinDiagOptions());

        await inspector.ListForProcessAsync(4321, includeAllObjectTypes: true, CancellationToken.None);

        var (executable, argv) = Assert.Single(runner.Invocations);

        Assert.Equal(ExpectedHandleBuild, executable);
        Assert.Equal(["-accepteula", "-nobanner", "-a", "-p", "4321", "-u", "-v"], argv);
    }

    [Fact]
    public async Task A_pid_reaches_handle_exe_as_a_number_and_never_as_caller_text()
    {
        // handle.exe -p also accepts a process NAME, which would silently widen a request about one
        // process into one about every process sharing its name. Formatting from an int is what stops
        // that being reachable at all.
        var runner = new StubExternalToolRunner(SampleCsv);
        var inspector = new HandleExeInspector(
            runner, Locator(), new FakePrivilegeProbe(true), new WinDiagOptions());

        await inspector.ListForProcessAsync(7, includeAllObjectTypes: false, CancellationToken.None);

        var (_, argv) = Assert.Single(runner.Invocations);

        Assert.Equal("7", argv.SkipWhile(a => a != "-p").Skip(1).First());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task A_pid_that_cannot_be_real_is_refused_before_the_process_starts(int processId)
    {
        var runner = new StubExternalToolRunner(SampleCsv);
        var inspector = new HandleExeInspector(
            runner, Locator(), new FakePrivilegeProbe(true), new WinDiagOptions());

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => inspector.ListForProcessAsync(processId, true, CancellationToken.None));

        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task A_search_term_shaped_like_a_switch_is_refused_before_the_process_starts()
    {
        // handle.exe -c closes a handle and can destabilise the machine. This must never be reachable
        // from a caller-supplied value.
        var runner = new StubExternalToolRunner();
        var inspector = new HandleExeInspector(
            runner, Locator(), new FakePrivilegeProbe(true), new WinDiagOptions());

        await Assert.ThrowsAsync<UnsafeArgumentException>(
            () => inspector.SearchAsync("-c", includeAllObjectTypes: false, CancellationToken.None));

        Assert.Empty(runner.Invocations);
    }
}
