using System.Diagnostics;
using Diag.Mcp.Server.Commands;

namespace LinuxDiag.Mcp.Diagnostics.Commands;

/// <summary>The Linux shells: POSIX sh, bash, and none.</summary>
/// <remarks>
/// sh is the default because it is always present, even on a minimal image where bash is not. Arguments
/// go through ArgumentList, which on Unix is argv exactly -- no re-quoting layer between the caller's
/// string and the shell, unlike cmd.exe on Windows.
/// </remarks>
public sealed class LinuxShellSet : IShellSet
{
    public const string Sh = "Sh";
    public const string Bash = "Bash";
    public const string None = "None";

    public void Apply(ProcessStartInfo start, string shell, string commandLine)
    {
        ArgumentNullException.ThrowIfNull(start);

        switch (shell)
        {
            case Sh:
                start.FileName = "/bin/sh";
                start.ArgumentList.Add("-c");
                start.ArgumentList.Add(commandLine);
                break;

            case Bash:
                start.FileName = "/bin/bash";
                start.ArgumentList.Add("-c");
                start.ArgumentList.Add(commandLine);
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
}
