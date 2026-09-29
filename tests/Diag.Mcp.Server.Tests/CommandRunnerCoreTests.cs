using System.Diagnostics;
using Diag.Mcp.Server.Capabilities;
using Diag.Mcp.Server.Commands;
using Microsoft.Extensions.Logging.Abstractions;

namespace Diag.Mcp.Server.Tests;

/// <summary>The shared runner, driven through a shell set of the test's own.</summary>
/// <remarks>
/// The runner owns timeouts, output capture and audit; which shells exist is the server's. These run a
/// real child process on either platform through the one shell this set offers.
/// </remarks>
public sealed class CommandRunnerCoreTests
{
    /// <summary>One shell, "Echo": the platform's own system shell, so the test runs anywhere.</summary>
    private sealed class OnlyEcho : IShellSet
    {
        public void Apply(ProcessStartInfo start, string shell, string commandLine)
        {
            if (shell != "Echo")
            {
                throw new CommandExecutionException($"Unknown shell '{shell}'.");
            }

            start.FileName = OperatingSystem.IsWindows() ? "cmd.exe" : "/bin/sh";
            start.ArgumentList.Add(OperatingSystem.IsWindows() ? "/c" : "-c");
            start.ArgumentList.Add(commandLine);
        }
    }

    private sealed class NotElevated : IPrivilegeProbe
    {
        public bool IsElevated => false;
    }

    private static CommandRunner Runner() => new(
        new OnlyEcho(), new CommandRunnerOptions(TimeSpan.FromSeconds(30)), new NotElevated(),
        NullLogger<CommandRunner>.Instance);

    [Fact]
    public async Task Runs_through_the_servers_shell_and_reports_it_by_the_name_it_was_given()
    {
        var result = await Runner().RunAsync(new CommandRequest("echo kit-runner", "Echo"), CancellationToken.None);

        Assert.Equal(0, result.ExitCode);
        Assert.Equal("Echo", result.Shell);
        Assert.Contains("kit-runner", result.StandardOutput, StringComparison.Ordinal);
        Assert.False(result.TimedOut);
        Assert.False(result.Elevated);
    }

    [Fact]
    public async Task A_shell_the_server_does_not_offer_is_refused_in_its_own_terms()
    {
        var ex = await Assert.ThrowsAsync<CommandExecutionException>(
            () => Runner().RunAsync(new CommandRequest("echo x", "cmd"), CancellationToken.None));

        Assert.Contains("Unknown shell 'cmd'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_non_zero_exit_is_a_result_not_an_exception()
    {
        var result = await Runner().RunAsync(new CommandRequest("exit 7", "Echo"), CancellationToken.None);

        Assert.Equal(7, result.ExitCode);
    }
}
