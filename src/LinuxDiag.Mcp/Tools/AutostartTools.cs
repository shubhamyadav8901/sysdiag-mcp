using System.ComponentModel;
using System.Globalization;
using System.Text;
using LinuxDiag.Mcp.Diagnostics.Autostart;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

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
        "List what is configured to run without anybody starting it - enabled systemd services, timers, sockets and " +
        "paths (with the unit a timer or socket actually runs), users' systemd units, cron (system and users' " +
        "crontabs, /etc/cron.d, cron.hourly/daily/weekly/monthly), /etc/rc.local, /etc/profile.d and /etc/ld.so.preload " +
        "- with the program each one runs. categories takes one or more of: all, services, timers, sockets, paths, " +
        "userunits, cron, rclocal, profiled, preload. verifyPackages checks every file that decides what runs - unit " +
        "file, drop-ins, program, and the script an interpreter runs - against the dpkg database; unpackagedOnly " +
        "returns only entries with a file that is not from a package or was changed, which is usually the fastest " +
        "route to an answer. Not covered: XDG autostart, udev RUN+=, anacrontab, at jobs, update-motd.d, " +
        "modules-load.d and modprobe install lines.")]
    public async Task<AutostartAuditToolResult> AutostartAudit(
        [Description("Comma-separated category names, or 'all'. Defaults to all.")] string categories = "all",
        [Description("Only entries whose name, program, file, description or command contains this text")] string? nameFilter = null,
        [Description("Check each entry's files against the dpkg database and report the owning package.")] bool verifyPackages = false,
        [Description("Return only entries with a file that is not from a package, or was changed. Implies verifyPackages.")] bool unpackagedOnly = false,
        [Description("Drop entries whose every file matches its package. Implies verifyPackages.")] bool hidePackaged = false,
        CancellationToken cancellationToken = default)
    {
        var result = await autostarts.AuditAsync(
            new AutostartQuery(categories, nameFilter, verifyPackages, unpackagedOnly, hidePackaged), cancellationToken).ConfigureAwait(false);
        return new AutostartAuditToolResult(Render(result, categories, nameFilter), result);
    }

    internal static string Render(AutostartAuditResult result, string categories, string? nameFilter)
    {
        var builder = new StringBuilder();
        if (!result.Elevated)
        {
            builder.AppendLine("WARNING: the server is not running as root, so users' crontabs and some home directories were not read and this list is partial.");
        }

        foreach (var limitation in result.Limitations)
        {
            builder.Append("WARNING: ").AppendLine(limitation);
        }

        var preloads = result.Entries.Count(e => e.Category == "preload");
        if (preloads > 0)
        {
            builder.Append("ATTENTION: /etc/ld.so.preload names ").Append(preloads)
                .AppendLine(preloads == 1 ? " library, loaded into every program on this machine." : " libraries, loaded into every program on this machine.");
        }

        if (result.Entries.Count == 0)
        {
            builder.Append("Nothing configured to start automatically matched");
            if (!string.IsNullOrWhiteSpace(nameFilter))
            {
                builder.Append(" '").Append(nameFilter).Append('\'');
            }

            return builder.Append(" in categories ").Append(categories).Append('.').ToString();
        }

        builder.Append(result.TotalMatched).Append(result.TotalMatched == 1 ? " entry" : " entries").AppendLine(":");
        string? category = null;
        foreach (var entry in result.Entries.Take(RenderLimits.MaxRenderedRows))
        {
            if (entry.Category != category)
            {
                category = entry.Category;
                builder.Append('[').Append(category).AppendLine("]");
            }

            builder.Append("- ").Append(entry.Entry);
            if (!entry.Enabled)
            {
                builder.Append(" (disabled)");
            }

            builder.Append("  ").Append(entry.ImagePath ?? "(no program recorded)");
            if (entry.ImageMissing) builder.Append("  [FILE NOT FOUND]");
            // The program's package is named whenever it has one: a foreign drop-in or a changed binary is not
            // "not from a package", and the '!' lines below say which file failed.
            if (entry.Package is { } package) builder.Append("  ").Append(package);
            if (entry.Packaged == false) builder.Append(entry.Package is null ? "  [NOT FROM A PACKAGE]" : "  [FILES DO NOT MATCH THE PACKAGE]");
            if (entry.Profile is { } profile) builder.Append("  (").Append(profile).Append(')');
            builder.AppendLine();
            builder.Append("    ").AppendLine(entry.Location);
            foreach (var finding in entry.PackageFindings)
            {
                builder.Append("    ! ").AppendLine(finding);
            }
        }

        RenderLimits.NoteElision(builder, result.Entries.Count, "returned entries");
        if (result.Truncated)
        {
            builder.Append("Showing the first ").Append(result.Entries.Count).Append(" of ")
                .Append(result.TotalMatched.ToString("N0", CultureInfo.InvariantCulture))
                .AppendLine("; narrow with categories or nameFilter, or raise LINUXDIAG_MAX_RESULTS.");
        }

        builder.Append(!result.PackagesVerified
            ? "Packages were not checked. Pass unpackagedOnly to see only what did not come from a package."
            : result.UnpackagedCount == 0
                ? "Every entry returned matches its packages."
                : $"{result.UnpackagedCount} of these have a file that is not from a package or was changed - each is listed with '!'.");
        return builder.ToString().TrimEnd();
    }
}
