using Diag.Mcp.Server.Commands;
using Microsoft.Extensions.Logging.Abstractions;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.Commands;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

public sealed class CommandShellParsingTests
{
    [Theory]
    [InlineData("cmd", WindowsShellSet.Cmd)]
    [InlineData("", WindowsShellSet.Cmd)]
    [InlineData(null, WindowsShellSet.Cmd)]
    [InlineData("PowerShell", WindowsShellSet.PowerShell)]
    [InlineData("pwsh", WindowsShellSet.PowerShell)]
    [InlineData("none", WindowsShellSet.None)]
    [InlineData(" NONE ", WindowsShellSet.None)]
    public void Maps_the_documented_shell_names(string? input, string expected)
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

/// <summary>
/// The command line each shell is handed, checked without starting anything.
/// </summary>
/// <remarks>
/// Pinned exactly because the bug was in the encoding, not in what reached the runner: ArgumentList
/// escaped every quote as <c>\"</c>, which is how the C runtime unescapes, and cmd.exe is not a C
/// runtime program -- it saw the backslashes.
/// </remarks>
public sealed class WindowsShellSetTests
{
    [Fact]
    public void Hands_cmd_the_command_verbatim_inside_one_outer_pair_of_quotes()
    {
        var start = new System.Diagnostics.ProcessStartInfo();

        new WindowsShellSet().Apply(start, WindowsShellSet.Cmd, "\"C:\\Program Files\\App\\app.exe\" --version");

        Assert.Equal("cmd.exe", start.FileName);
        Assert.Equal("/d /s /c \"\"C:\\Program Files\\App\\app.exe\" --version\"", start.Arguments);

        // Both may not be set at once, and ArgumentList is the one that re-escapes.
        Assert.Empty(start.ArgumentList);
    }

    [Fact]
    public void Leaves_powershell_on_the_argument_list_whose_escaping_it_does_understand()
    {
        // powershell.exe parses its command line the C runtime's way, so ArgumentList's \" is correct
        // for it -- this pins that the cmd fix did not drag PowerShell onto a raw string as well.
        var start = new System.Diagnostics.ProcessStartInfo();

        new WindowsShellSet().Apply(start, WindowsShellSet.PowerShell, "Write-Output \"a b\"");

        Assert.Equal(["-NoProfile", "-NonInteractive", "-Command", "Write-Output \"a b\""], start.ArgumentList);
        Assert.Equal(string.Empty, start.Arguments);
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
    private static CommandRunner Runner(int timeoutSeconds = 30) =>
        new(new WindowsShellSet(),
            new CommandRunnerOptions(TimeSpan.FromSeconds(timeoutSeconds)),
            new WindowsPrivilegeProbe(),
            NullLogger<CommandRunner>.Instance);

    [Fact]
    public async Task Runs_a_cmd_command_and_captures_stdout_and_exit_code()
    {
        var r = await Runner().RunAsync(
            new CommandRequest("echo windiag-marker", WindowsShellSet.Cmd), CancellationToken.None);

        Assert.Equal(0, r.ExitCode);
        Assert.Contains("windiag-marker", r.StandardOutput);
        Assert.False(r.TimedOut);
    }

    [Fact]
    public async Task Surfaces_a_nonzero_exit_code_without_throwing()
    {
        // `exit /b 3` under cmd. A failed command is a result, not an exception.
        var r = await Runner().RunAsync(
            new CommandRequest("exit /b 3", WindowsShellSet.Cmd), CancellationToken.None);

        Assert.Equal(3, r.ExitCode);
    }

    [Fact]
    public async Task Honours_cmd_chaining_and_pipes()
    {
        // The reason 'cmd' is the default shell: && and | must work, which they cannot in None mode.
        var r = await Runner().RunAsync(
            new CommandRequest("echo one && echo two", WindowsShellSet.Cmd), CancellationToken.None);

        Assert.Contains("one", r.StandardOutput);
        Assert.Contains("two", r.StandardOutput);
    }

    [Fact]
    public async Task Passes_cmd_a_quoted_argument_unchanged()
    {
        // Every quote used to reach cmd as \" -- ArgumentList's C-runtime escaping, which cmd does not
        // understand -- so `echo "a b"` printed \"a b\" and a quoted path was "not recognized".
        var r = await Runner().RunAsync(
            new CommandRequest("echo \"a b\"", WindowsShellSet.Cmd), CancellationToken.None);

        Assert.Equal(0, r.ExitCode);
        Assert.Equal("\"a b\"", r.StandardOutput.Trim());
    }

    [Fact]
    public async Task Runs_a_quoted_program_path_containing_spaces_with_its_own_quoted_argument()
    {
        // The everyday Windows case, and the one cmd's quote stripping mangles without /s: the line
        // both starts with a quote and holds more than two, so cmd would strip the first and the last
        // and run `C:\...\print args.cmd" "x y` instead.
        var directory = Path.Combine(Path.GetTempPath(), $"windiag cmd {Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var script = Path.Combine(directory, "print args.cmd");
        File.WriteAllText(script, "@echo windiag-marker %1\r\n");

        try
        {
            var r = await Runner().RunAsync(
                new CommandRequest($"\"{script}\" \"x y\"", WindowsShellSet.Cmd), CancellationToken.None);

            Assert.Equal(0, r.ExitCode);
            Assert.Contains("windiag-marker \"x y\"", r.StandardOutput);

            var listing = await Runner().RunAsync(
                new CommandRequest($"dir \"{directory}\"", WindowsShellSet.Cmd), CancellationToken.None);

            Assert.Equal(0, listing.ExitCode);
            Assert.Contains("print args.cmd", listing.StandardOutput);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Runs_a_quoted_comspec_at_the_start_of_the_line()
    {
        var r = await Runner().RunAsync(
            new CommandRequest("\"%ComSpec%\" /c echo windiag-ok", WindowsShellSet.Cmd), CancellationToken.None);

        Assert.Equal(0, r.ExitCode);
        Assert.Contains("windiag-ok", r.StandardOutput);
    }

    [Fact]
    public async Task Passes_powershell_a_double_quoted_string_unchanged()
    {
        var r = await Runner().RunAsync(
            new CommandRequest("Write-Output \"a b\"; Write-Output 'say \"hi\"'", WindowsShellSet.PowerShell),
            CancellationToken.None);

        Assert.Equal(0, r.ExitCode);
        Assert.Contains("a b", r.StandardOutput);
        Assert.Contains("say \"hi\"", r.StandardOutput);
    }

    [Fact]
    public async Task Runs_in_the_requested_working_directory()
    {
        var temp = Path.Combine(Path.GetTempPath(), $"windiag-cmd-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temp);
        try
        {
            var r = await Runner().RunAsync(
                new CommandRequest("cd", WindowsShellSet.Cmd, WorkingDirectory: temp), CancellationToken.None);

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
            () => Runner().RunAsync(new CommandRequest("echo x", WindowsShellSet.Cmd, WorkingDirectory: missing), CancellationToken.None));

        Assert.Contains("does not exist", ex.Message);
    }

    [Fact]
    public async Task Refuses_an_empty_command()
    {
        await Assert.ThrowsAsync<CommandExecutionException>(
            () => Runner().RunAsync(new CommandRequest("   ", WindowsShellSet.Cmd), CancellationToken.None));
    }

    [Fact]
    public async Task Runs_a_powershell_command()
    {
        var r = await Runner().RunAsync(
            new CommandRequest("Write-Output (2 + 3)", WindowsShellSet.PowerShell), CancellationToken.None);

        Assert.Equal(0, r.ExitCode);
        Assert.Contains("5", r.StandardOutput);
    }

    [Fact]
    public async Task None_mode_runs_the_first_token_as_an_executable()
    {
        // hostname.exe takes no args and prints the machine name; proves direct exec with no shell.
        var r = await Runner().RunAsync(
            new CommandRequest("hostname", WindowsShellSet.None), CancellationToken.None);

        Assert.Equal(0, r.ExitCode);
        Assert.False(string.IsNullOrWhiteSpace(r.StandardOutput));
    }

    [Fact]
    public async Task Kills_a_command_that_overruns_its_timeout_and_says_so()
    {
        // A 30s ping under a 2s budget. The result is partial, TimedOut is set, and it comes back
        // near the budget rather than the full 30s.
        var r = await Runner(timeoutSeconds: 2).RunAsync(
            new CommandRequest("ping -n 30 127.0.0.1", WindowsShellSet.Cmd), CancellationToken.None);

        Assert.True(r.TimedOut);
        Assert.True(r.DurationSeconds < 15, $"took {r.DurationSeconds}s, expected to be killed near 2s");
    }

    [Fact]
    public async Task Rejects_a_timeout_outside_the_allowed_range()
    {
        var ex = await Assert.ThrowsAsync<CommandExecutionException>(
            () => Runner().RunAsync(new CommandRequest("echo x", WindowsShellSet.Cmd, TimeoutSeconds: 99999), CancellationToken.None));

        Assert.Contains("out of range", ex.Message);
    }
}
