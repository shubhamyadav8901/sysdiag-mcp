using System.Diagnostics;
using Diag.Mcp.Server.Commands;

namespace MacDiag.Mcp.Diagnostics.Commands;

/// <summary>The macOS shells: zsh, POSIX sh, bash, and none.</summary>
/// <remarks>
/// zsh is the default because it has been macOS's login shell since 10.15, so a command copied from a Mac
/// user's terminal means the same here. /bin/bash is 3.2 on every macOS. Arguments go through ArgumentList,
/// which on Unix is argv exactly.
/// </remarks>
public sealed class MacShellSet : IShellSet
{
    public const string Zsh = "Zsh";
    public const string Sh = "Sh";
    public const string Bash = "Bash";
    public const string None = "None";

    public void Apply(ProcessStartInfo start, string shell, string commandLine)
    {
        ArgumentNullException.ThrowIfNull(start);

        switch (shell)
        {
            case Zsh:
                Shell(start, "/bin/zsh", commandLine);
                break;

            case Sh:
                Shell(start, "/bin/sh", commandLine);
                break;

            case Bash:
                Shell(start, "/bin/bash", commandLine);
                break;

            case None:
                var (exe, args) = CommandRunner.SplitFirstToken(commandLine);
                start.FileName = exe;
                if (!string.IsNullOrEmpty(args))
                {
                    start.Arguments = args;
                }
                break;

            default:
                throw new CommandExecutionException($"Unknown shell '{shell}'.");
        }
    }

    private static void Shell(ProcessStartInfo start, string path, string commandLine)
    {
        start.FileName = path;
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add(commandLine);
    }
}
