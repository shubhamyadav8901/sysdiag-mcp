using System.ComponentModel;
using Diag.Mcp.Server.Commands;
using LinuxDiag.Mcp.Diagnostics.Commands;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

/// <summary>Structured result of <c>run_command</c>.</summary>
public sealed record RunCommandResult(string Summary, CommandResult Command);

/// <summary>Running an arbitrary command on the host. Registered only when explicitly enabled.</summary>
[McpServerToolType]
public sealed class CommandTools(ICommandRunner commands)
{
    [McpServerTool(
        Name = "run_command",
        Title = "Run a command on the host",
        ReadOnly = false,
        Destructive = true,
        Idempotent = false,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Run an arbitrary command on the machine hosting this server, as the account the server runs " +
        "under (normally root), and return its exit code, stdout and stderr. This is a general shell, not " +
        "a diagnostic query - use it for package tools, build tools, or anything the other tools do not " +
        "cover. shell selects how the command is read: 'sh' (default) runs it through /bin/sh -c, so " +
        "pipes, redirection and && all work; 'bash' uses /bin/bash -c for bash syntax; 'none' runs the " +
        "first token as a program with the rest as literal arguments. Set workingDirectory to run " +
        "somewhere other than the server's own folder. A non-zero exit code is returned, not treated as " +
        "an error. Output is capped; the result says when it was truncated.")]
    public async Task<RunCommandResult> RunCommand(
        [Description("The command line to run, interpreted according to shell.")]
        string command,
        [Description("'sh' (default), 'bash', or 'none'")]
        string shell = "sh",
        [Description("Directory to run in; defaults to the server's own directory. Must already exist.")]
        string? workingDirectory = null,
        [Description("Per-command timeout override in seconds (1..3600); omit for the server default.")]
        int? timeoutSeconds = null,
        CancellationToken cancellationToken = default)
    {
        var result = await commands.RunAsync(
            new CommandRequest(command, ParseShell(shell), workingDirectory, timeoutSeconds), cancellationToken)
            .ConfigureAwait(false);

        return new RunCommandResult(Render(result), result);
    }

    internal static string ParseShell(string? shell) =>
        shell?.Trim().ToLowerInvariant() switch
        {
            null or "" or "sh" => LinuxShellSet.Sh,
            "bash" => LinuxShellSet.Bash,
            "none" or "exec" or "direct" => LinuxShellSet.None,
            _ => throw new ArgumentException(
                $"'{shell}' is not a shell here. Use 'sh', 'bash', or 'none'.", nameof(shell))
        };

    internal static string Render(CommandResult result) => CommandSummary.Render(result);
}
