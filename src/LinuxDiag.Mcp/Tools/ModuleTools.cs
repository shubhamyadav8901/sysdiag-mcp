using System.ComponentModel;
using System.Text;
using LinuxDiag.Mcp.Diagnostics.Handles;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

/// <summary>Structured result of <c>process_modules</c>.</summary>
public sealed record ProcessModulesResult(string Summary, ModuleListResult Modules);

[McpServerToolType]
public sealed class ModuleTools(IModuleInspector modules)
{
    [McpServerTool(
        Name = "process_modules",
        Title = "Files mapped into a process",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "List the files a process has memory-mapped - its executable, shared libraries and any mapped data files - " +
        "with each one's path, load address and mapped size. Use it when the library on disk and the one in use " +
        "might differ: after a package upgrade a running process keeps the old version mapped, and it is flagged " +
        "as deleted here - the reason a patched library can still be the one running until a restart. Filter by " +
        "name or path.")]
    public ProcessModulesResult ProcessModules(
        [Description("Process id. Get a current one from process_list; PIDs are reused.")] int processId,
        [Description("Only files whose path contains this text")] string? nameFilter = null)
    {
        var result = modules.Read(processId, nameFilter);
        return new ProcessModulesResult(Render(result, nameFilter), result);
    }

    internal static string Render(ModuleListResult result, string? nameFilter)
    {
        var builder = new StringBuilder();
        builder.Append(result.TotalMatched).Append(result.TotalMatched == 1 ? " mapped file" : " mapped files")
            .Append(" in ").Append(RenderLimits.Printable(result.ProcessName)).Append(" (PID ").Append(result.ProcessId).Append(')');
        if (!string.IsNullOrWhiteSpace(nameFilter))
        {
            builder.Append(" matching '").Append(RenderLimits.Printable(nameFilter)).Append('\'');
        }

        builder.AppendLine(":");
        foreach (var module in result.Modules.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(RenderLimits.Printable(module.Name)).Append("  ").Append(RenderLimits.Printable(module.Path));
            if (module.Deleted)
            {
                builder.Append("  [DELETED: replaced on disk since it was mapped]");
            }

            builder.AppendLine();
        }

        RenderLimits.NoteElision(builder, result.Modules.Count, "returned files");
        if (result.DeletedCount > 0)
        {
            builder.Append(result.DeletedCount).AppendLine(
                " of these were deleted or replaced on disk after the process mapped them. After a package upgrade " +
                "that means the process is still running the old code; restart it to pick up the new files.");
        }

        if (result.Truncated)
        {
            builder.Append("Showing the first ").Append(result.Modules.Count).Append(" of ").Append(result.TotalMatched)
                .Append("; narrow with nameFilter or raise LINUXDIAG_MAX_RESULTS.");
        }

        return builder.ToString().TrimEnd();
    }
}
