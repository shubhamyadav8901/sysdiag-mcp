using LinuxDiag.Mcp.Linux.External;

namespace LinuxDiag.Mcp.Tests;

public sealed class ExternalCommandTests
{
    [Fact]
    public async Task A_timeout_that_is_zero_or_negative_is_refused_before_anything_starts()
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            new LinuxExternalCommand().RunAsync("sh", [], TimeSpan.FromSeconds(-1), CancellationToken.None));
    }

    [Theory]
    [InlineData("-H", "starts with '-'")]
    [InlineData("a\nb", "control character")]
    [InlineData(" ", "empty")]
    public void A_caller_value_that_would_read_as_an_option_or_smuggle_a_control_character_is_refused(string value, string reason)
    {
        var ex = Assert.Throws<ArgumentException>(() => ExternalArgument.Check(value, "unit"));

        Assert.Contains(reason, ex.Message, StringComparison.Ordinal);
    }

    [LinuxFact]
    public async Task A_program_runs_from_the_system_directories_with_a_fixed_path_and_locale()
    {
        var result = await new LinuxExternalCommand().RunAsync("env", [], TimeSpan.FromSeconds(10), CancellationToken.None);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n", result.StandardOutput, StringComparison.Ordinal);
        Assert.Contains("LC_ALL=C.UTF-8\n", result.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("HOME=", result.StandardOutput, StringComparison.Ordinal);
    }

    [LinuxFact]
    public async Task A_program_that_is_not_installed_or_named_by_path_is_refused_by_name()
    {
        var missing = await Assert.ThrowsAsync<ExternalCommandException>(() =>
            new LinuxExternalCommand().RunAsync("no-such-program-ld", [], TimeSpan.FromSeconds(5), CancellationToken.None));
        var path = await Assert.ThrowsAsync<ExternalCommandException>(() =>
            new LinuxExternalCommand().RunAsync("/tmp/evil", [], TimeSpan.FromSeconds(5), CancellationToken.None));

        Assert.Contains("not installed", missing.Message, StringComparison.Ordinal);
        Assert.Contains("not installed", path.Message, StringComparison.Ordinal);
    }

    [LinuxFact]
    public async Task A_program_past_its_timeout_is_stopped_and_says_so()
    {
        var ex = await Assert.ThrowsAsync<ExternalCommandException>(() =>
            new LinuxExternalCommand().RunAsync("sleep", ["30"], TimeSpan.FromMilliseconds(300), CancellationToken.None));

        Assert.Contains("did not finish within", ex.Message, StringComparison.Ordinal);
        Assert.True(ex.TimedOut);
    }

    [LinuxFact]
    public async Task Output_past_the_cap_is_an_error_not_a_truncated_answer()
    {
        var ex = await Assert.ThrowsAsync<ExternalCommandException>(() =>
            new LinuxExternalCommand(maxOutputChars: 10_000).RunAsync("yes", [], TimeSpan.FromSeconds(1), CancellationToken.None));

        Assert.Contains("more than", ex.Message, StringComparison.Ordinal);
    }

    [LinuxFact]
    public async Task A_program_that_leaves_its_output_open_behind_it_is_an_error_not_an_empty_answer()
    {
        // The background sleep inherits stdout, so the pipe stays open after sh exits. What was read so far
        // must not come back as the whole answer.
        var ex = await Assert.ThrowsAsync<ExternalCommandException>(() =>
            new LinuxExternalCommand().RunAsync("sh", ["-c", "sleep 30 & echo partial"], TimeSpan.FromSeconds(20), CancellationToken.None));

        Assert.Contains("left its output open", ex.Message, StringComparison.Ordinal);
    }
}
