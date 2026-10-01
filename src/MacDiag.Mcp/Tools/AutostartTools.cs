using System.ComponentModel;
using System.Globalization;
using System.Text;
using MacDiag.Mcp.Diagnostics.Autostart;
using ModelContextProtocol.Server;

namespace MacDiag.Mcp.Tools;

/// <summary>Structured result of <c>autostart_audit</c>.</summary>
public sealed record AutostartAuditToolResult(string Summary, AutostartAuditResult Autostarts);

[McpServerToolType]
public sealed class AutostartTools(IAutostartInspector autostarts)
{
    [McpServerTool(
        Name = "autostart_audit",
        Title = "What starts on its own",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "List what starts on its own on this Mac - launchd daemons and agents (system and every user's), cron, " +
        "periodic scripts, login and logout hooks and authorization plugins - with the program each runs, when it " +
        "runs, whether it is enabled, and whether another account could change it (the file, the program, the script " +
        "an interpreter runs, or a directory above any of them). categories takes one or more of: all, daemons, " +
        "agents, useragents, cron, periodic, loginhooks, authplugins. hideApple (default true) leaves out what comes " +
        "from the sealed system volume, and, with signatures checked, Apple's own programs; a label is never trusted, " +
        "since whoever writes a plist chooses it. verifySignatures checks each program with codesign; unsignedOnly " +
        "returns only unsigned programs, scripts, missing programs and files another account could change - usually " +
        "the fastest route to an answer.")]
    public async Task<AutostartAuditToolResult> AutostartAudit(
        [Description("Comma-separated category names, or 'all'. Defaults to all.")] string categories = "all",
        [Description("Only entries whose label, program, file, schedule or command contains this text")] string? nameFilter = null,
        [Description("Leave out what comes from the sealed system volume, and Apple-signed programs when signatures are checked. Defaults to true.")] bool hideApple = true,
        [Description("Check each program's code signature and report who signed it.")] bool verifySignatures = false,
        [Description("Return only unsigned programs and scripts, missing programs, and entries another account could change. Implies verifySignatures.")] bool unsignedOnly = false,
        CancellationToken cancellationToken = default)
    {
        var result = await autostarts.AuditAsync(
            new AutostartQuery(categories, nameFilter, hideApple, verifySignatures, unsignedOnly), cancellationToken).ConfigureAwait(false);
        return new AutostartAuditToolResult(Render(result, categories, nameFilter), result);
    }

    internal static string Render(AutostartAuditResult result, string categories, string? nameFilter)
    {
        var builder = new StringBuilder();
        if (!result.Elevated)
        {
            builder.AppendLine("WARNING: the server is not running as root, so users' crontabs, root's login hooks and unreadable homes were not read and this list is partial.");
        }

        foreach (var limitation in result.Limitations)
        {
            builder.Append("WARNING: ").AppendLine(RenderLimits.Printable(limitation));
        }

        if (result.WritableByOthersCount > 0)
        {
            builder.Append("ATTENTION: ").Append(result.WritableByOthersCount)
                .AppendLine(result.WritableByOthersCount == 1
                    ? " entry runs something another account could change - see the '!' lines."
                    : " entries run something another account could change - see the '!' lines.");
        }

        if (result.Entries.Count == 0)
        {
            builder.Append("Nothing configured to start automatically matched");
            if (!string.IsNullOrWhiteSpace(nameFilter))
            {
                builder.Append(" '").Append(RenderLimits.Printable(nameFilter)).Append('\'');
            }

            return builder.Append(" in categories ").Append(RenderLimits.Printable(categories)).Append('.').ToString();
        }

        builder.Append(result.TotalMatched).Append(result.TotalMatched == 1 ? " entry" : " entries").AppendLine(":");
        string? category = null;
        foreach (var entry in result.Entries.Take(RenderLimits.MaxRenderedRows))
        {
            if (entry.Category != category)
            {
                category = entry.Category;
                builder.Append('[').Append(RenderLimits.Printable(category)).AppendLine("]");
            }

            builder.Append("- ").Append(RenderLimits.Printable(entry.Entry));
            if (!entry.Enabled)
            {
                builder.Append(" (disabled)");
            }

            builder.Append("  ").Append(RenderLimits.Printable(entry.ImagePath ?? "(no program recorded)"));
            if (entry.ScriptPath is { } script) builder.Append(" running ").Append(RenderLimits.Printable(script));
            if (entry.ImageMissing) builder.Append("  [FILE NOT FOUND]");
            if (entry.Signed == false) builder.Append("  [UNSIGNED]");
            else if (entry.Signed == true && entry.SignatureDetail is { } signer) builder.Append("  (").Append(RenderLimits.Printable(signer)).Append(')');
            if (entry.Profile is { } profile) builder.Append("  user ").Append(RenderLimits.Printable(profile));
            builder.AppendLine();
            builder.Append("    ").Append(RenderLimits.Printable(entry.Location));
            if (entry.Description is { } description) builder.Append(" - ").Append(RenderLimits.Printable(description));
            builder.AppendLine();
            foreach (var finding in entry.Findings)
            {
                builder.Append("    ! ").AppendLine(RenderLimits.Printable(finding));
            }
        }

        RenderLimits.NoteElision(builder, result.Entries.Count, "returned entries");
        if (result.Truncated)
        {
            builder.Append("Showing the first ").Append(result.Entries.Count).Append(" of ")
                .Append(result.TotalMatched.ToString("N0", CultureInfo.InvariantCulture))
                .AppendLine("; narrow with categories or nameFilter, or raise MACDIAG_MAX_RESULTS.");
        }

        builder.Append(!result.SignaturesVerified
            ? "Signatures were not checked. Pass unsignedOnly to see only unsigned programs and what another account could change."
            : result.UnsignedCount == 0
                ? "Every program returned has a signature that verifies."
                : $"{result.UnsignedCount} of these run an unsigned program or a script.");
        return builder.ToString().TrimEnd();
    }
}
