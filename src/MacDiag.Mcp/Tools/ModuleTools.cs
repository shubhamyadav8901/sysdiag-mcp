using System.ComponentModel;
using System.Text;
using MacDiag.Mcp.Diagnostics.Handles;
using ModelContextProtocol.Server;

namespace MacDiag.Mcp.Tools;

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
        "List the executable and libraries a process has mapped, with each one's path and size. Use it when the " +
        "library on disk and the one in use might differ, or to see which non-system library a process loaded. " +
        "System libraries are mapped from the dyld shared cache and are not listed individually; the executable, " +
        "dyld and any non-system library are. Filter by name or path.")]
    public async Task<ProcessModulesResult> ProcessModules(
        [Description("Process id. Get a current one from process_list; PIDs are reused.")] int processId,
        [Description("Only files whose path contains this text")] string? nameFilter = null,
        CancellationToken cancellationToken = default)
    {
        var result = await modules.ReadAsync(processId, nameFilter, cancellationToken).ConfigureAwait(false);
        return new ProcessModulesResult(Render(result, nameFilter), result);
    }

    internal static string Render(ModuleListResult result, string? nameFilter)
    {
        var builder = new StringBuilder();
        builder.Append(RenderLimits.Printable(result.ProcessName)).Append(" [").Append(result.ProcessId).Append("]: ")
            .Append(result.TotalMatched).Append(result.TotalMatched == 1 ? " mapped file" : " mapped files");
        if (!string.IsNullOrWhiteSpace(nameFilter))
        {
            builder.Append(" matching '").Append(RenderLimits.Printable(nameFilter)).Append('\'');
        }

        builder.AppendLine();
        foreach (var module in result.Modules.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(RenderLimits.Printable(module.Path));
            if (module.SizeBytes is { } size)
            {
                builder.Append(" (").Append(TextFormat.Bytes(size)).Append(')');
            }

            builder.AppendLine();
        }

        RenderLimits.NoteElision(builder, result.Modules.Count, "mapped files");
        if (result.Truncated)
        {
            builder.Append("Showing the first ").Append(result.Modules.Count).Append(" of ").Append(result.TotalMatched)
                .AppendLine("; narrow the filter or raise MACDIAG_MAX_RESULTS.");
        }

        foreach (var limitation in result.Limitations)
        {
            builder.Append("NOTE: ").AppendLine(RenderLimits.Printable(limitation));
        }

        return builder.ToString().TrimEnd();
    }
}
