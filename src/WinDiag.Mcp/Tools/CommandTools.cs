using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics.Commands;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>run_command</c>.</summary>
public sealed record RunCommandResult(string Summary, CommandResult Command);

/// <summary>Running an arbitrary command on the host. Registered only when explicitly enabled.</summary>
/// <remarks>
/// The one tool that is a shell rather than a question. Gated behind
/// <c>WINDIAG_ALLOW_COMMAND_EXECUTION</c> and refused under read-only mode, both enforced at
/// registration in <c>ServerBuilder</c> — so if this type is reachable at all, arbitrary execution has
/// already been granted for this deployment.
/// </remarks>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class CommandTools
{
    private readonly ICommandRunner _commands;

    public CommandTools(ICommandRunner commands)
    {
        _commands = commands;
    }

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
        "under (often SYSTEM or an administrator), and return its exit code, stdout and stderr. " +
        "This is a general shell, not a diagnostic query - use it for git, build tools, Klocwork, or " +
        "anything the other tools do not cover. " +
        "shell selects how the command is read: 'cmd' (default) runs it through cmd.exe, so pipes, " +
        "redirection, chaining with && and built-ins all work; 'powershell' runs it through " +
        "powershell.exe -Command; 'none' runs the first token as an executable with the rest as literal " +
        "arguments, for a path or argument that must not be re-parsed. " +
        "Set workingDirectory to run somewhere other than the server's own folder - e.g. a repo root. " +
        "A non-zero exit code is returned, not treated as an error: a command that ran and failed is a " +
        "result you can read. Output is capped; the result says when it was truncated.")]
    public async Task<RunCommandResult> RunCommand(
        [Description("The command line to run, interpreted according to shell.")]
        string command,
        [Description("'cmd' (default), 'powershell', or 'none'")]
        string shell = "cmd",
        [Description("Directory to run in; defaults to the server's own directory. Must already exist.")]
        string? workingDirectory = null,
        [Description("Per-command timeout override in seconds (1..3600); omit for the server default.")]
        int? timeoutSeconds = null,
        CancellationToken cancellationToken = default)
    {
        var request = new CommandRequest(
            CommandLine: command,
            Shell: ParseShell(shell),
            WorkingDirectory: workingDirectory,
            TimeoutSeconds: timeoutSeconds);

        var result = await _commands.RunAsync(request, cancellationToken).ConfigureAwait(false);

        return new RunCommandResult(Render(result), result);
    }

    /// <summary>Maps the caller's shell word onto the enum, or refuses it.</summary>
    internal static CommandShell ParseShell(string? shell) =>
        shell?.Trim().ToLowerInvariant() switch
        {
            null or "" or "cmd" => CommandShell.Cmd,
            "powershell" or "pwsh" or "ps" => CommandShell.PowerShell,
            "none" or "exec" or "direct" => CommandShell.None,
            _ => throw new ArgumentException(
                $"'{shell}' is not a shell. Use 'cmd', 'powershell', or 'none'.", nameof(shell))
        };

    internal static string Render(CommandResult result)
    {
        var builder = new StringBuilder();

        if (result.TimedOut)
        {
            // Leads, because the output below is partial and reading it as complete is the trap.
            builder.AppendLine(
                "WARNING: the command exceeded its timeout and was killed. The output below is whatever " +
                "it had produced by then, not a complete run.");
        }

        builder.Append("$ ").AppendLine(result.CommandLine);
        builder.Append("exit ").Append(result.ExitCode.ToString(CultureInfo.InvariantCulture))
            .Append("  (").Append(result.Shell.ToLowerInvariant()).Append(", ")
            .Append(result.DurationSeconds.ToString("0.##", CultureInfo.InvariantCulture)).Append("s, in ")
            .Append(result.WorkingDirectory).AppendLine(")");

        if (result.StandardOutput.Length > 0)
        {
            builder.AppendLine().AppendLine("stdout:").Append(result.StandardOutput.TrimEnd());
        }

        if (result.StandardError.Length > 0)
        {
            builder.AppendLine().AppendLine("stderr:").Append(result.StandardError.TrimEnd());
        }

        if (result.StandardOutput.Length == 0 && result.StandardError.Length == 0)
        {
            builder.AppendLine().Append("(no output)");
        }

        if (result.OutputTruncated)
        {
            builder.AppendLine().Append("[output was truncated; redirect to a file and read it in pieces " +
                                        "if you need all of it]");
        }

        return builder.ToString().TrimEnd();
    }
}
