using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics.Modules;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>process_modules</c>.</summary>
public sealed record ProcessModulesResult(string Summary, ModuleListResult Modules);

/// <summary>What a process has actually loaded.</summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class ModuleTools
{
    private readonly IModuleInspector _modules;

    public ModuleTools(IModuleInspector modules)
    {
        _modules = modules;
    }

    [McpServerTool(
        Name = "process_modules",
        Title = "DLLs loaded in a process",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "List the DLLs a process has actually loaded, with the full path, version and load address of " +
        "each. Use it when the version on disk and the version in use might differ - a stale copy " +
        "beside the executable, a shell extension loaded from somewhere unexpected, or an add-in that " +
        "is not the build you shipped. " +
        "Set verifySignatures to check each one's Authenticode signature, which finds unsigned or " +
        "tampered modules loaded into a signed process. That is slower, so it applies only to the " +
        "modules actually returned - filter by name first if you know what you are looking for.")]
    public ProcessModulesResult ProcessModules(
        [Description("Process id. Get a current one from process_list; PIDs are reused.")]
        int processId,
        [Description("Only modules whose name or path contains this text")]
        string? nameFilter = null,
        [Description("Verify each returned module's Authenticode signature. Slower; handles catalog-signed Windows DLLs correctly.")]
        bool verifySignatures = false,
        CancellationToken cancellationToken = default)
    {
        var result = _modules.List(processId, nameFilter, verifySignatures, cancellationToken);

        return new ProcessModulesResult(Render(result, nameFilter, verifySignatures), result);
    }

    internal static string Render(ModuleListResult result, string? nameFilter, bool verified)
    {
        var builder = new StringBuilder();

        if (result.Limitation is { } limitation)
        {
            // Leads, because a short list caused by a failed enumeration looks exactly like a process
            // that has loaded very little.
            builder.Append("WARNING: ").AppendLine(limitation);
        }

        builder.Append(result.TotalMatched)
            .Append(result.TotalMatched == 1 ? " module" : " modules")
            .Append(" in ").Append(result.ProcessName).Append(" (PID ").Append(result.ProcessId).Append(')');

        if (!string.IsNullOrWhiteSpace(nameFilter))
        {
            builder.Append(" matching '").Append(nameFilter).Append('\'');
        }

        builder.AppendLine(":");

        foreach (var module in result.Modules)
        {
            builder.Append("- ").Append(module.Name).Append("  ").Append(module.Path);

            if (module.FileVersion is { } version)
            {
                builder.Append("  v").Append(version);
            }

            if (module.SignatureVerdict is { } verdict && verdict != "Valid")
            {
                builder.Append("  [").Append(verdict.ToUpperInvariant()).Append(']');
            }

            builder.AppendLine();
        }

        if (verified)
        {
            builder.AppendLine();
            builder.Append(result.UnsignedCount switch
            {
                0 => "Every module returned is signed and trusted.",
                1 => "1 of the modules returned is unsigned or untrusted - that is the one worth looking " +
                     "at first.",
                var n => $"{n} of the modules returned are unsigned or untrusted - those are the ones " +
                         "worth looking at first."
            });
        }
        else
        {
            builder.AppendLine().Append("Signatures were not checked. Pass verifySignatures to find " +
                                        "unsigned or tampered modules.");
        }

        if (result.Truncated)
        {
            builder.AppendLine().Append("Showing the first ").Append(result.Modules.Count).Append(" of ")
                .Append(result.TotalMatched.ToString("N0", CultureInfo.InvariantCulture))
                .Append("; narrow with nameFilter or raise WINDIAG_MAX_RESULTS.");
        }

        return builder.ToString().TrimEnd();
    }
}
