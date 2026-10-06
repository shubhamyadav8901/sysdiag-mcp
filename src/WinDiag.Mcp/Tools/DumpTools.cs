using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics.Dumps;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>capture_dump</c>.</summary>
public sealed record CaptureDumpResult(string Summary, DumpResult Dump);

/// <summary>Capturing a process snapshot for post-mortem analysis.</summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class DumpTools
{
    private readonly IDumpWriter _dumps;

    public DumpTools(IDumpWriter dumps)
    {
        _dumps = dumps;
    }

    [McpServerTool(
        Name = "capture_dump",
        Title = "Capture a process dump",
        // Not read-only: this writes a file that can be several gigabytes.
        ReadOnly = false,
        Destructive = false,
        Idempotent = false,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Capture a crash dump of a running process and return where it was written. Use it for a hung " +
        "or misbehaving process you want to analyse properly: 'mini' captures stacks, threads, handles " +
        "and loaded modules and is enough to see where a hang is stuck; 'full' adds all process memory " +
        "and is much larger. " +
        "The result includes a UNC path on this machine's administrative share, which a debugger on " +
        "another machine can open directly - pass it to mcp-windbg's open_windbg_dump rather than " +
        "copying the file. Capturing a process owned by another user or by SYSTEM requires elevation. " +
        "Dumping a 32-bit process (an Office add-in or a shell extension host, for example) works, and " +
        "the result says how to make the debugger show its real stacks.")]
    public CaptureDumpResult CaptureDump(
        [Description("Process id to dump. Get a current one from process_list; PIDs are reused.")]
        int processId,
        [Description("'mini' for stacks, threads, handles and modules; 'full' to include all process memory")]
        string kind = "mini",
        CancellationToken cancellationToken = default)
    {
        var dump = _dumps.Capture(processId, ParseKind(kind), cancellationToken);

        return new CaptureDumpResult(Render(dump), dump);
    }

    internal static DumpKind ParseKind(string kind) =>
        kind?.Trim().ToLowerInvariant() switch
        {
            null or "" or "mini" or "minidump" or "small" => DumpKind.Mini,
            "full" or "fulldump" or "complete" => DumpKind.Full,
            _ => throw new ArgumentException(
                $"'{kind}' is not a dump kind. Use 'mini' or 'full'.", nameof(kind))
        };

    internal static string Render(DumpResult dump)
    {
        var builder = new StringBuilder();

        builder.Append("Captured a ").Append(dump.Kind.ToString().ToLowerInvariant()).Append(" dump of ")
            .Append(RenderLimits.Printable(dump.ProcessName)).Append(" (PID ").Append(dump.ProcessId).Append("), ")
            .Append(FormatBytes(dump.SizeBytes)).AppendLine(".");

        builder.Append("On this machine: ").AppendLine(RenderLimits.Printable(dump.Path));

        if (dump.UncPath is { } unc)
        {
            // The whole point of the UNC form: it saves copying gigabytes between machines.
            builder.Append("From another machine: ").AppendLine(RenderLimits.Printable(unc));
            builder.AppendLine(
                "Analyse it with mcp-windbg's open_windbg_dump, passing the UNC path - cdb opens it " +
                "directly, so there is no need to copy the file.");
        }
        else
        {
            builder.AppendLine(
                "This path is not on a local drive letter, so it has no administrative-share equivalent. " +
                "Copy the file to analyse it from another machine.");
        }

        if (dump.TargetIsWow64)
        {
            // Silently handing over a dump whose stacks look like thunk noise wastes the analyst's
            // first ten minutes. Say it up front, with the command that fixes it.
            builder.AppendLine();
            builder.AppendLine(
                "IMPORTANT: this is a 32-bit process on 64-bit Windows, dumped by a 64-bit process. " +
                "A debugger will show WOW64 thunk frames rather than the real 32-bit call stacks. " +
                "In WinDbg or cdb, run  !wow64exts.sw  to switch to the 32-bit view (run it again to " +
                "switch back). If the stacks still look wrong, re-capture with a 32-bit dumper such as " +
                "the 32-bit procdump.");
        }

        if (!dump.Elevated)
        {
            builder.Append(
                "NOTE: the server is not elevated. This dump succeeded, but processes owned by other " +
                "users or by SYSTEM cannot be captured without elevation.");
        }

        return builder.ToString().TrimEnd();
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        var unit = 0;

        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value.ToString(unit == 0 ? "0" : "0.#", CultureInfo.InvariantCulture)} {units[unit]}";
    }
}
