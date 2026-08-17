using Microsoft.Extensions.Logging.Abstractions;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.Commands;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

public sealed class CommandShellParsingTests
{
    [Theory]
    [InlineData("cmd", CommandShell.Cmd)]
    [InlineData("", CommandShell.Cmd)]
    [InlineData(null, CommandShell.Cmd)]
    [InlineData("PowerShell", CommandShell.PowerShell)]
    [InlineData("pwsh", CommandShell.PowerShell)]
    [InlineData("none", CommandShell.None)]
    [InlineData(" NONE ", CommandShell.None)]
    public void Maps_the_documented_shell_names(string? input, CommandShell expected)
    {
        Assert.Equal(expected, CommandTools.ParseShell(input));
    }

    [Fact]
    public void Refuses_a_shell_it_does_not_know()
    {
        var ex = Assert.Throws<ArgumentException>(() => CommandTools.ParseShell("bash"));

        Assert.Contains("'cmd'", ex.Message);
    }
}

public sealed class CommandRenderingTests
{
    private static CommandResult Result(
        int exitCode = 0,
        string stdout = "",
        string stderr = "",
        bool truncated = false,
        bool timedOut = false) =>
        new("git status", "Cmd", @"C:\repo", exitCode, stdout, stderr, truncated, timedOut, 0.4, true);

    [Fact]
    public void Shows_the_command_exit_code_and_working_directory()
    {
        var summary = CommandTools.Render(Result(exitCode: 0, stdout: "clean"));

        Assert.Contains("$ git status", summary);
        Assert.Contains("exit 0", summary);
        Assert.Contains(@"C:\repo", summary);
        Assert.Contains("clean", summary);
    }

    [Fact]
    public void A_nonzero_exit_is_rendered_as_a_result_not_hidden()
    {
        // A command that ran and failed is a result the caller reads, not an error that vanishes.
        var summary = CommandTools.Render(Result(exitCode: 128, stderr: "fatal: not a git repository"));

        Assert.Contains("exit 128", summary);
        Assert.Contains("not a git repository", summary);
    }

    [Fact]
    public void A_timeout_leads_with_a_warning_that_the_output_is_partial()
    {
        var summary = CommandTools.Render(Result(exitCode: -1, stdout: "half a build", timedOut: true));

        Assert.StartsWith("WARNING", summary);
        Assert.Contains("not a complete run", summary);
    }

    [Fact]
    public void Says_no_output_rather_than_rendering_a_blank()
    {
        Assert.Contains("(no output)", CommandTools.Render(Result()));
    }

    [Fact]
    public void Flags_truncated_output()
    {
        Assert.Contains("truncated", CommandTools.Render(Result(stdout: "lots", truncated: true)));
    }
}

/// <summary>
/// The runner against real cmd/powershell on this machine. Runs harmless read-only commands only.
/// </summary>
public sealed class CommandRunnerTests
{
    private static WindowsCommandRunner Runner(int timeoutSeconds = 30) =>
        new(WinDiagOptions.FromEnvironment(new System.Collections.Hashtable
            {
                ["WINDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS"] = timeoutSeconds.ToString()
            }),
            new WindowsPrivilegeProbe(),
            NullLogger<WindowsCommandRunner>.Instance);

    [Fact]
    public async Task Runs_a_cmd_command_and_captures_stdout_and_exit_code()
    {
        var r = await Runner().RunAsync(
            new CommandRequest("echo windiag-marker"), CancellationToken.None);

        Assert.Equal(0, r.ExitCode);
        Assert.Contains("windiag-marker", r.StandardOutput);
        Assert.False(r.TimedOut);
    }

    [Fact]
    public async Task Surfaces_a_nonzero_exit_code_without_throwing()
    {
        // `exit /b 3` under cmd. A failed command is a result, not an exception.
        var r = await Runner().RunAsync(
            new CommandRequest("exit /b 3"), CancellationToken.None);

        Assert.Equal(3, r.ExitCode);
    }

    [Fact]
    public async Task Honours_cmd_chaining_and_pipes()
    {
        // The reason 'cmd' is the default shell: && and | must work, which they cannot in None mode.
        var r = await Runner().RunAsync(
            new CommandRequest("echo one && echo two"), CancellationToken.None);

        Assert.Contains("one", r.StandardOutput);
        Assert.Contains("two", r.StandardOutput);
    }

    [Fact]
    public async Task Runs_in_the_requested_working_directory()
    {
        var temp = Path.Combine(Path.GetTempPath(), $"windiag-cmd-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temp);
        try
        {
            var r = await Runner().RunAsync(
                new CommandRequest("cd", WorkingDirectory: temp), CancellationToken.None);

            // `cd` with no argument prints the current directory.
            Assert.Contains(temp, r.StandardOutput, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(temp);
        }
    }

    [Fact]
    public async Task Refuses_a_working_directory_that_does_not_exist()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"windiag-absent-{Guid.NewGuid():N}");

        var ex = await Assert.ThrowsAsync<CommandExecutionException>(
            () => Runner().RunAsync(new CommandRequest("echo x", WorkingDirectory: missing), CancellationToken.None));

        Assert.Contains("does not exist", ex.Message);
    }

    [Fact]
    public async Task Refuses_an_empty_command()
    {
        await Assert.ThrowsAsync<CommandExecutionException>(
            () => Runner().RunAsync(new CommandRequest("   "), CancellationToken.None));
    }

    [Fact]
    public async Task Runs_a_powershell_command()
    {
        var r = await Runner().RunAsync(
            new CommandRequest("Write-Output (2 + 3)", CommandShell.PowerShell), CancellationToken.None);

        Assert.Equal(0, r.ExitCode);
        Assert.Contains("5", r.StandardOutput);
    }

    [Fact]
    public async Task None_mode_runs_the_first_token_as_an_executable()
    {
        // hostname.exe takes no args and prints the machine name; proves direct exec with no shell.
        var r = await Runner().RunAsync(
            new CommandRequest("hostname", CommandShell.None), CancellationToken.None);

        Assert.Equal(0, r.ExitCode);
        Assert.False(string.IsNullOrWhiteSpace(r.StandardOutput));
    }

    [Fact]
    public async Task Kills_a_command_that_overruns_its_timeout_and_says_so()
    {
        // A 30s ping under a 2s budget. The result is partial, TimedOut is set, and it comes back
        // near the budget rather than the full 30s.
        var r = await Runner(timeoutSeconds: 2).RunAsync(
            new CommandRequest("ping -n 30 127.0.0.1"), CancellationToken.None);

        Assert.True(r.TimedOut);
        Assert.True(r.DurationSeconds < 15, $"took {r.DurationSeconds}s, expected to be killed near 2s");
    }

    [Fact]
    public async Task Rejects_a_timeout_outside_the_allowed_range()
    {
        var ex = await Assert.ThrowsAsync<CommandExecutionException>(
            () => Runner().RunAsync(new CommandRequest("echo x", TimeoutSeconds: 99999), CancellationToken.None));

        Assert.Contains("out of range", ex.Message);
    }
}
