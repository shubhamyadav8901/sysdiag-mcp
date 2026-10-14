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

    [Fact]
    public async Task An_empty_search_with_unreadable_rows_never_says_nothing_matched()
    {
        // A row handle.exe printed but this parser could not attribute -- an image name with a comma
        // makes one -- is a holder that exists. Reporting "No open file references matched" over it is
        // the confident negative that ends an investigation.
        var tools = Build(handles: new HandleSearchResult(
            "x.docx", [], true, false, 0, IncludedAllObjectTypes: false, UnparsedRows: 1));

        var result = await tools.PathHandleSearch("x.docx");

        Assert.StartsWith("WARNING", result.Summary);
        Assert.Contains("1 row", result.Summary);
        Assert.DoesNotContain("No open file references matched", result.Summary);
        Assert.Equal(1, result.UnparsedRows);
    }

    [Fact]
    public void A_process_with_unreadable_rows_is_never_said_to_hold_nothing()
    {
        var summary = FileLockTools.RenderHandleSummary(new HandleSearchResult(
            "PID 1234", [], true, false, 0, IncludedAllObjectTypes: true, ProcessScoped: true, UnparsedRows: 3));

        Assert.Contains("3 rows", summary);
        Assert.DoesNotContain("holds no open handles", summary);
        Assert.DoesNotContain("holds no open file references", summary);
    }

    [Fact]
    public void Counts_the_unproven_rows_names_the_first_and_says_only_the_pid_is_certain()
    {
        // The structured list carries the mark per row; the text says it once, at the row it starts from.
        var summary = FileLockTools.RenderHandleSummary(new HandleSearchResult(
            "PID 1234",
            [
                new HandleEntry("svc.exe", 1234, "Key", null, "0x0000000C", @"HKCU\Software\Contoso"),
                new HandleEntry("svc.exe", 1234, "File", null, "0x00000010", @"C:\shared\x.docx", Unproven: true)
            ],
            true, false, 2, IncludedAllObjectTypes: true, ProcessScoped: true));

        Assert.Contains("1 of these rows is marked unproven, the first at handle 0x00000010 of svc.exe (PID 1234)", summary);
        Assert.Contains("line break", summary);
        Assert.Contains("PID is certain", summary);
        Assert.Contains("not proven", summary);
    }

    [Fact]
    public void Never_says_every_row_after_the_first_unproven_one_is_unproven_when_a_later_one_is_proven()
    {
        // Rows ahead of a line whose image name the process table could not confirm are unproven, and the
        // rows after it need not be: "from this handle on" would mark a proven row as doubtful and, worse,
        // teach the reader that the mark runs to the end when it does not.
        var summary = FileLockTools.RenderHandleSummary(new HandleSearchResult(
            "PID 1234",
            [
                new HandleEntry("svc.exe", 1234, "File", null, "0x00000004", @"C:\shared\x.docx", Unproven: true),
                new HandleEntry("z", 1234, "File", null, "0x00000008", @"C:\Windows\System32", Unproven: true),
                new HandleEntry("svc.exe", 1234, "File", null, "0x0000000C", @"C:\Windows\Fonts\arial.ttf")
            ],
            true, false, 3, IncludedAllObjectTypes: false, ProcessScoped: true, UnconfirmedImage: true));

        Assert.DoesNotContain(") on,", summary);
        Assert.Contains("2 of these rows are marked unproven, the first at handle 0x00000004", summary);
        Assert.Contains("image name", summary);
    }

    [Fact]
    public void Says_an_unconfirmed_image_name_may_be_a_process_that_came_or_went_not_only_a_forgery()
    {
        // The usual cause is benign -- a holder started or exited while handle.exe ran -- and a warning
        // that names only the attack would send the reader hunting for one that is not there.
        var summary = FileLockTools.RenderHandleSummary(new HandleSearchResult(
            "x.docx", [], true, false, 0, IncludedAllObjectTypes: false, UnparsedRows: 2, UnconfirmedImage: true));

        Assert.StartsWith("WARNING", summary);
        Assert.Contains("started or exited while handle.exe ran", summary);
        Assert.Contains("line break inside an image name", summary);
    }

    [Fact]
    public void A_fully_proven_list_carries_no_note()
    {
        var summary = FileLockTools.RenderHandleSummary(new HandleSearchResult(
            "x.docx", [new HandleEntry("word.exe", 5150, "File", null, "0x00000460", @"C:\shared\x.docx")],
            true, false, 1, IncludedAllObjectTypes: false));

        Assert.DoesNotContain("NOTE", summary);
        Assert.DoesNotContain("WARNING", summary);
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
            runner, Locator(), new FakePrivilegeProbe(true), new WinDiagOptions(), new FakeProcessTable((7, "app.exe")));

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
            runner, locator, new FakePrivilegeProbe(true), new WinDiagOptions(), new FakeProcessTable((7, "app.exe")));

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
            runner, thirtyTwoBit, new FakePrivilegeProbe(true), new WinDiagOptions(), new FakeProcessTable((7, "app.exe")));

        var ex = await Assert.ThrowsAsync<ToolArchitectureException>(
            () => inspector.SearchAsync("Fonts", includeAllObjectTypes: false, CancellationToken.None));

        Assert.Contains("handle64.exe", ex.Message);
        Assert.Contains("No matching handles found", ex.Message);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task A_row_is_confirmed_against_the_process_table_on_both_sides_of_the_run()
    {
        // PID 7 was app.exe when handle.exe started and is app.exe again when it ends -- but not the same
        // app.exe: its creation time moved, so the row may have been printed by a process in between,
        // whose image name nothing here has read.
        var reused = new FakeProcessTable(
        [
            new Dictionary<int, ProcessImage> { [7] = new(1, "app.exe") },
            new Dictionary<int, ProcessImage> { [7] = new(2, "app.exe") }
        ]);
        var inspector = new HandleExeInspector(
            new StubExternalToolRunner(SampleCsv), Locator(), new FakePrivilegeProbe(true), new WinDiagOptions(), reused);

        var result = await inspector.SearchAsync("t", includeAllObjectTypes: false, CancellationToken.None);

        Assert.Equal(2, reused.Taken);
        Assert.Empty(result.Entries);
        Assert.Equal(1, result.UnparsedRows);
        Assert.True(result.UnconfirmedImage);
    }

    [Fact]
    public async Task The_search_tools_own_row_is_confirmed_by_the_pid_the_runner_started_it_as()
    {
        // handle64.exe can list its own handles, and under the SCM its working directory is C:\Windows\System32,
        // so a search for that folder printed a row for a process in neither reading of the table. Left
        // unconfirmed, it made every row before it unattributable, on every run of that search. (The row
        // before it has no name, so that this machine's lack of an NTFS C: does not doubt the line after it.)
        var csv = "Process,PID,User,Handle,Type,Share Flags,Name,Access\r\n" +
                  "app.exe,7,File,CONTOSO\\u,0x9,\r\n" +
                  $"{ExpectedHandleBuild},9,File,NT AUTHORITY\\SYSTEM,0x4,C:\\Windows\\System32\r\n";
        var inspector = new HandleExeInspector(
            new StubExternalToolRunner(csv, processId: 9), Locator(), new FakePrivilegeProbe(true), new WinDiagOptions(),
            new FakeProcessTable((7, "app.exe")));

        var result = await inspector.SearchAsync("System32", includeAllObjectTypes: false, CancellationToken.None);

        Assert.Equal(2, result.Entries.Count);
        Assert.All(result.Entries, entry => Assert.False(entry.Unproven));
        Assert.Equal(0, result.UnparsedRows);
        Assert.False(result.UnconfirmedImage);
    }

    [Fact]
    public async Task A_row_of_a_process_that_ran_throughout_under_its_printed_name_is_listed()
    {
        var inspector = new HandleExeInspector(
            new StubExternalToolRunner(SampleCsv), Locator(), new FakePrivilegeProbe(true), new WinDiagOptions(),
            new FakeProcessTable((7, "app.exe")));

        var result = await inspector.SearchAsync("t", includeAllObjectTypes: false, CancellationToken.None);

        var entry = Assert.Single(result.Entries);
        Assert.False(entry.Unproven);
        Assert.False(result.UnconfirmedImage);
    }

    [Fact]
    public async Task All_types_search_adds_the_flag_that_reaches_registry_keys()
    {
        // Without -a, handle.exe dumps file references only -- no registry keys, whatever the tool
        // description promises. It is opt-in because a machine-wide -a search had produced 223 rows,
        // all still Files, after 6m40s.
        var runner = new StubExternalToolRunner(SampleCsv);
        var inspector = new HandleExeInspector(
            runner, Locator(), new FakePrivilegeProbe(true), new WinDiagOptions(), new FakeProcessTable((7, "app.exe")));

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
            runner, Locator(), new FakePrivilegeProbe(true), new WinDiagOptions(), new FakeProcessTable((7, "app.exe")));

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
            runner, Locator(), new FakePrivilegeProbe(true), new WinDiagOptions(), new FakeProcessTable((7, "app.exe")));

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
            runner, Locator(), new FakePrivilegeProbe(true), new WinDiagOptions(), new FakeProcessTable((7, "app.exe")));

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
            runner, Locator(), new FakePrivilegeProbe(true), new WinDiagOptions(), new FakeProcessTable((7, "app.exe")));

        await Assert.ThrowsAsync<UnsafeArgumentException>(
            () => inspector.SearchAsync("-c", includeAllObjectTypes: false, CancellationToken.None));

        Assert.Empty(runner.Invocations);
    }
}
