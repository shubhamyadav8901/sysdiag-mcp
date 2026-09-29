using System.Globalization;
using System.Text;

namespace Diag.Mcp.Server.Commands;

/// <summary>The one-screen summary of a run_command result, shared so every server words it the same.</summary>
public static class CommandSummary
{
    public static string Render(CommandResult result)
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
