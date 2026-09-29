using System.Diagnostics;
using Diag.Mcp.Server.Commands;
using LinuxDiag.Mcp.Diagnostics;
using LinuxDiag.Mcp.Diagnostics.Commands;
using LinuxDiag.Mcp.Tools;
using Microsoft.Extensions.Logging.Abstractions;

namespace LinuxDiag.Mcp.Tests;

public sealed class CommandShellParsingTests
{
    [Theory]
    [InlineData("sh", LinuxShellSet.Sh)]
    [InlineData("", LinuxShellSet.Sh)]
    [InlineData(null, LinuxShellSet.Sh)]
    [InlineData("BASH", LinuxShellSet.Bash)]
    [InlineData("none", LinuxShellSet.None)]
    [InlineData(" exec ", LinuxShellSet.None)]
    public void Maps_the_documented_shell_names(string? input, string expected) =>
        Assert.Equal(expected, CommandTools.ParseShell(input));

    [Fact]
    public void Refuses_a_windows_shell_in_linux_terms()
    {
        var ex = Assert.Throws<ArgumentException>(() => CommandTools.ParseShell("cmd"));

        Assert.Contains("'sh'", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(LinuxShellSet.Sh, "/bin/sh")]
    [InlineData(LinuxShellSet.Bash, "/bin/bash")]
    public void Each_shell_runs_the_program_it_names(string shell, string program)
    {
        // A pipeline runs the same under sh and bash, so only this can tell the two apart.
        var start = new ProcessStartInfo();
        new LinuxShellSet().Apply(start, shell, "x");

        Assert.Equal(program, start.FileName);
        Assert.Equal(["-c", "x"], start.ArgumentList);
    }
}

public sealed class LinuxCommandRunnerTests
{
    private static CommandRunner Runner() => new(
        new LinuxShellSet(), new CommandRunnerOptions(TimeSpan.FromSeconds(30)), new LinuxPrivilegeProbe(),
        NullLogger<CommandRunner>.Instance);

    [LinuxFact]
    public async Task Sh_runs_a_pipeline()
    {
        var r = await Runner().RunAsync(new CommandRequest("echo abc | tr a z", LinuxShellSet.Sh), CancellationToken.None);

        Assert.Equal(0, r.ExitCode);
        Assert.Equal("zbc", r.StandardOutput.Trim());
        Assert.Equal("Sh", r.Shell);
    }

    [LinuxFact]
    public async Task Bash_runs_bash_syntax()
    {
        var r = await Runner().RunAsync(new CommandRequest("[[ 2 -gt 1 ]] && echo bash-only", LinuxShellSet.Bash), CancellationToken.None);

        Assert.Equal("bash-only", r.StandardOutput.Trim());
    }

    [LinuxFact]
    public async Task None_runs_one_program_with_literal_arguments()
    {
        var r = await Runner().RunAsync(new CommandRequest("uname -s", LinuxShellSet.None), CancellationToken.None);

        Assert.Equal("Linux", r.StandardOutput.Trim());
    }

    [LinuxFact]
    public async Task Quotes_reach_the_shell_intact()
    {
        // The Windows server's cmd path mangles embedded quotes; here ArgumentList passes argv exactly,
        // so a quoted path with a space works.
        var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"ld cmd {Guid.NewGuid():N}")).FullName;
        try
        {
            var r = await Runner().RunAsync(new CommandRequest($"test -d \"{dir}\" && echo yes", LinuxShellSet.Sh), CancellationToken.None);
            Assert.Equal("yes", r.StandardOutput.Trim());
        }
        finally
        {
            Directory.Delete(dir);
        }
    }
}
