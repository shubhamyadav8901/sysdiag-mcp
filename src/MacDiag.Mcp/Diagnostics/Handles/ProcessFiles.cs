using System.Globalization;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Mac;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Handles;

/// <summary>One process's open files from lsof -p, or why there are none.</summary>
internal static class ProcessFiles
{
    public static async Task<LsofProcess> ReadAsync(
        IExternalCommand commands, MacDiagOptions options, int processId, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(processId);

        var listed = await Lsof.RunAsync(commands, ["-p", processId.ToString(CultureInfo.InvariantCulture)], fullListing: false,
            options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        if (listed.FirstOrDefault(p => p.ProcessId == processId) is { } process)
        {
            return process;
        }

        // lsof prints nothing both for a PID that is gone and for another user's process it may not read, so ask ps
        // which: "not running" would send the caller hunting for a process that is right there.
        var ps = await commands.RunAsync("ps", ["-p", processId.ToString(CultureInfo.InvariantCulture), "-o", "pid="],
            options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        throw new HandleQueryException(ps.ExitCode == 0 && ps.StandardOutput.Trim().Length > 0
            ? $"PID {processId} is running but its open files are not readable without root. Run the server as root."
            : $"No process with PID {processId} is running. Call process_list for a current one; PIDs are reused.");
    }
}
