using System.Diagnostics;
using System.Runtime.Versioning;
using Diag.Mcp.Server.External;

namespace Diag.Mcp.Server.Tests;

[UnsupportedOSPlatform("windows")]
public sealed class SystemCommandTests
{
    private static readonly string[] Unix = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

    private sealed class Capped(int max) : SystemCommand(Unix, max);

    private sealed class UnicodeEnv : SystemCommand
    {
        public UnicodeEnv()
            : base(Unix)
        {
        }

        protected override string? CharacterLocaleFor(string program) => program == "env" ? "en_US.UTF-8" : null;
    }

    [UnixFact]
    public async Task A_program_given_its_own_character_locale_gets_only_lc_ctype_changed_and_others_keep_lc_all()
    {
        var env = await new UnicodeEnv().RunAsync("env", [], TimeSpan.FromSeconds(10), CancellationToken.None);
        var other = await new UnicodeEnv().RunAsync("sh", ["-c", "env"], TimeSpan.FromSeconds(10), CancellationToken.None);

        // LC_ALL would override LC_CTYPE, so it must be absent; LANG keeps every other category (LC_TIME) at C.
        Assert.Contains("LC_CTYPE=en_US.UTF-8\n", env.StandardOutput, StringComparison.Ordinal);
        Assert.Contains("LANG=C\n", env.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("LC_ALL=", env.StandardOutput, StringComparison.Ordinal);
        Assert.Contains("LC_ALL=C\n", other.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("LC_CTYPE=", other.StandardOutput, StringComparison.Ordinal);
    }

    [UnixFact]
    public async Task Lines_arrive_one_by_one_and_returning_false_stops_the_program_early()
    {
        var seen = new List<string>();
        var watch = Stopwatch.StartNew();

        var result = await new SystemCommand(Unix).RunLinesAsync(
            "seq", ["1", "100000000"], TimeSpan.FromSeconds(20), line => { seen.Add(line); return seen.Count < 5; },
            CancellationToken.None);

        Assert.Equal(["1", "2", "3", "4", "5"], seen);
        Assert.True(result.StoppedEarly);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10), $"took {watch.Elapsed}");
    }

    [UnixFact]
    public async Task A_program_that_runs_to_the_end_reports_its_exit_code_and_standard_error()
    {
        var lines = new List<string>();

        var result = await new SystemCommand(Unix).RunLinesAsync(
            "sh", ["-c", "echo a; echo b; echo oops >&2; exit 3"], TimeSpan.FromSeconds(10), line => { lines.Add(line); return true; },
            CancellationToken.None);

        Assert.Equal(["a", "b"], lines);
        Assert.Equal(3, result.ExitCode);
        Assert.Contains("oops", result.StandardError, StringComparison.Ordinal);
        Assert.False(result.StoppedEarly);
    }

    [UnixFact]
    public async Task Streamed_output_past_the_cap_is_an_error_not_a_quiet_stop()
    {
        var ex = await Assert.ThrowsAsync<ExternalCommandException>(() => new Capped(10_000).RunLinesAsync(
            "yes", [], TimeSpan.FromSeconds(5), _ => true, CancellationToken.None));

        Assert.Contains("more than", ex.Message, StringComparison.Ordinal);
    }

    [UnixFact]
    public async Task A_streamed_program_past_its_timeout_is_stopped_and_says_so()
    {
        var ex = await Assert.ThrowsAsync<ExternalCommandException>(() => new SystemCommand(Unix).RunLinesAsync(
            "sleep", ["30"], TimeSpan.FromMilliseconds(300), _ => true, CancellationToken.None));

        Assert.True(ex.TimedOut);
    }

    [UnixFact]
    public async Task A_program_that_closes_its_output_but_keeps_running_still_times_out()
    {
        // End of output is not the end of the program: waiting for exit without the deadline would hang here.
        var watch = Stopwatch.StartNew();

        var ex = await Assert.ThrowsAsync<ExternalCommandException>(() => new SystemCommand(Unix).RunLinesAsync(
            "sh", ["-c", "exec >/dev/null; sleep 30"], TimeSpan.FromMilliseconds(500), _ => true, CancellationToken.None));

        Assert.True(ex.TimedOut);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10), $"took {watch.Elapsed}");
    }

    [UnixFact]
    public async Task A_callback_that_throws_leaves_no_program_running()
    {
        // exec keeps the shell's PID, so the first line names the process that must be gone afterwards.
        var pid = 0;

        await Assert.ThrowsAsync<InvalidOperationException>(() => new SystemCommand(Unix).RunLinesAsync(
            "sh", ["-c", "echo $$; exec sleep 30"], TimeSpan.FromSeconds(60),
            line => { pid = int.Parse(line, System.Globalization.CultureInfo.InvariantCulture); throw new InvalidOperationException("boom"); },
            CancellationToken.None));

        try
        {
            using var survivor = Process.GetProcessById(pid);
            Assert.True(survivor.WaitForExit(3000), $"process {pid} was still running after the callback threw");
        }
        catch (ArgumentException)
        {
            // Already gone and reaped.
        }
    }

    [UnixFact]
    public void The_resolver_finds_programs_only_in_the_directories_it_was_given()
    {
        var resolver = new SystemExecutableResolver(Unix);

        var sh = resolver.Resolve("sh").Path;
        Assert.NotNull(sh);
        Assert.EndsWith("/sh", sh, StringComparison.Ordinal);
        Assert.Contains(Path.GetDirectoryName(sh), Unix);
        Assert.Null(new SystemExecutableResolver(["/nonexistent"]).Resolve("sh").Path);
        Assert.Null(resolver.Resolve("/bin/sh").Path); // a name holding '/' is never resolved
    }
}
