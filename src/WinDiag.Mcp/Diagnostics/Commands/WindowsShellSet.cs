using System.Diagnostics;
using Diag.Mcp.Server.Commands;

namespace WinDiag.Mcp.Diagnostics.Commands;

/// <summary>The Windows shells: cmd, PowerShell, and none.</summary>
/// <remarks>
/// The shell choice is explicit because it changes what the string means. <c>Cmd</c> and
/// <c>PowerShell</c> get pipes, redirection, chaining and built-ins; <c>None</c> runs a single
/// executable with the remaining words as literal arguments, which is the only mode where an argument
/// containing spaces or metacharacters is safe from re-parsing.
/// </remarks>
public sealed class WindowsShellSet : IShellSet
{
    /// <summary><c>cmd.exe /d /s /c "&lt;command&gt;"</c>. The default: it is what a person types.</summary>
    public const string Cmd = "Cmd";

    /// <summary><c>powershell.exe -NoProfile -Command &lt;command&gt;</c>.</summary>
    public const string PowerShell = "PowerShell";

    /// <summary>Run the first token as an executable, the rest as literal arguments. No shell.</summary>
    public const string None = "None";

    public void Apply(ProcessStartInfo start, string shell, string commandLine)
    {
        ArgumentNullException.ThrowIfNull(start);

        switch (shell)
        {
            case Cmd:
                // A raw string, not ArgumentList. ArgumentList escapes each quote as \" -- how the C
                // runtime unescapes -- but cmd.exe reads its own command line and knows nothing of
                // backslash escapes, so `"C:\Program Files\x.exe" --version` arrived as
                // `\"C:\Program` and was "not recognized". /s makes cmd strip exactly the outer pair
                // added here and run the rest as typed, where without it a line that starts with a quote
                // and holds more than two loses its first and last. /d skips the AutoRun commands in the
                // registry, which would otherwise run first and change what the caller's command sees.
                start.FileName = "cmd.exe";
                start.Arguments = "/d /s /c \"" + commandLine + "\"";
                break;

            case PowerShell:
                start.FileName = "powershell.exe";
                start.ArgumentList.Add("-NoProfile");
                start.ArgumentList.Add("-NonInteractive");
                start.ArgumentList.Add("-Command");
                start.ArgumentList.Add(commandLine);
                break;

            case None:
                var (exe, args) = CommandRunner.SplitFirstToken(commandLine);
                start.FileName = exe;
                if (!string.IsNullOrEmpty(args))
                {
                    // Passed as a single Arguments string on purpose: in None mode the caller is stating
                    // "these are the literal arguments", and ArgumentList would re-quote them.
                    start.Arguments = args;
                }
                break;

            default:
                throw new CommandExecutionException($"Unknown shell '{shell}'.");
        }
    }
}
