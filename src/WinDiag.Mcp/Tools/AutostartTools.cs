using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics.Autostart;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>autostart_audit</c>.</summary>
public sealed record AutostartAuditToolResult(string Summary, AutostartAuditResult Autostarts);

/// <summary>What runs on this machine without anybody starting it.</summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class AutostartTools
{
    /// <summary>
    /// Friendly category names to Autoruns' letters.
    /// </summary>
    /// <remarks>
    /// A fixed table rather than passing the caller's text through, so no caller-supplied value ever
    /// reaches the argument vector. It also lets the names describe what someone is looking for --
    /// "office", "explorer" -- rather than requiring them to know that Explorer add-ons are 'e'.
    /// </remarks>
    private static readonly IReadOnlyDictionary<string, string> Categories =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["all"] = "*",
            ["boot"] = "b",
            ["codecs"] = "c",
            ["appinit"] = "d",
            ["explorer"] = "e",
            ["gadgets"] = "g",
            ["imagehijacks"] = "h",
            ["internetexplorer"] = "i",
            ["knowndlls"] = "k",
            ["logon"] = "l",
            ["wmi"] = "m",
            ["winsock"] = "n",
            ["office"] = "o",
            ["printmonitors"] = "p",
            ["lsaproviders"] = "r",
            ["services"] = "s",
            ["scheduledtasks"] = "t",
            ["winlogon"] = "w",
            ["storeapps"] = "x"
        };

    private readonly IAutostartInspector _autostarts;

    public AutostartTools(IAutostartInspector autostarts)
    {
        _autostarts = autostarts;
    }

    [McpServerTool(
        Name = "autostart_audit",
        Title = "What starts on its own",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "List what is configured to run without anybody starting it - services, drivers, logon items, " +
        "scheduled tasks, Explorer and Office add-ins, image hijacks - with the file each one points " +
        "at and who signed it. " +
        "Use it when something runs that should not, when an uninstall left a hook behind, or when an " +
        "add-in loads a build you did not ship. " +
        "categories takes one or more of: all, boot, codecs, appinit, explorer, gadgets, imagehijacks, " +
        "internetexplorer, knowndlls, logon, wmi, winsock, office, printmonitors, lsaproviders, " +
        "services, scheduledtasks, winlogon, storeapps. " +
        "Signature verification is off by default because it costs an Authenticode check per entry and " +
        "there are hundreds; unsignedOnly turns it on and returns only what failed, which is usually " +
        "the fastest route to an answer - measured at 59s for every category on a lab VM. " +
        "Entries whose target file is missing are marked [FILE NOT FOUND]: usually an uninstall that " +
        "left its hook behind, but also what a hijack looks like before the replacement is dropped in.")]
    public async Task<AutostartAuditToolResult> AutostartAudit(
        [Description("Comma-separated category names, or 'all'. Defaults to all.")]
        string categories = "all",
        [Description("Only entries whose name, image path, registry key, description or publisher contains this text")]
        string? nameFilter = null,
        [Description("Verify each entry's signature and report the publisher. Slower.")]
        bool verifySignatures = false,
        [Description("Return only entries that are NOT validly signed. Implies verifySignatures.")]
        bool unsignedOnly = false,
        [Description("Drop entries that are both signed and Microsoft's. Implies verifySignatures.")]
        bool hideMicrosoft = false,
        CancellationToken cancellationToken = default)
    {
        var query = new AutostartQuery(
            Categories: ParseCategories(categories),
            NameFilter: nameFilter,
            VerifySignatures: verifySignatures,
            UnsignedOnly: unsignedOnly,
            HideMicrosoft: hideMicrosoft);

        var result = await _autostarts.AuditAsync(query, cancellationToken).ConfigureAwait(false);

        return new AutostartAuditToolResult(Render(result, categories, nameFilter), result);
    }

    /// <summary>Maps friendly names onto the letter string Autoruns expects.</summary>
    /// <remarks>Internal for direct testing: this is the only place caller text influences the argv.</remarks>
    internal static string ParseCategories(string categories)
    {
        if (string.IsNullOrWhiteSpace(categories))
        {
            return "*";
        }

        var letters = new List<string>();

        foreach (var name in categories.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!Categories.TryGetValue(name, out var letter))
            {
                throw new ArgumentException(
                    $"'{name}' is not a category. Use one or more of: " +
                    $"{string.Join(", ", Categories.Keys)}.",
                    nameof(categories));
            }

            // 'all' subsumes everything, so mixing it with others would only produce a longer way of
            // saying the same thing -- and Autoruns treats '*' plus letters as an error.
            if (letter == "*")
            {
                return "*";
            }

            if (!letters.Contains(letter, StringComparer.Ordinal))
            {
                letters.Add(letter);
            }
        }

        return letters.Count == 0 ? "*" : string.Concat(letters);
    }

    internal static string Render(AutostartAuditResult result, string categories, string? nameFilter)
    {
        var builder = new StringBuilder();

        if (!result.Elevated)
        {
            // Leads, for the same reason path_handle_search's warning does: entries under other users'
            // profiles and some protected keys are simply absent, and absence reads as "not configured".
            builder.AppendLine(
                "WARNING: autorunsc ran WITHOUT administrator rights, so this list is partial. Entries " +
                "under other users' profiles and in protected keys are missing, and an absent entry " +
                "here does not mean it is not configured. Restart the server elevated for a complete " +
                "answer.");
        }

        builder.Append(result.TotalMatched)
            .Append(result.TotalMatched == 1 ? " autostart entry" : " autostart entries")
            .Append(" in ").Append(RenderLimits.Printable(categories));

        if (!string.IsNullOrWhiteSpace(nameFilter))
        {
            builder.Append(" matching '").Append(RenderLimits.Printable(nameFilter)).Append('\'');
        }

        builder.AppendLine(":");

        foreach (var group in result.Entries.Take(RenderLimits.MaxRenderedRows)
                     .GroupBy(e => e.Category, StringComparer.OrdinalIgnoreCase))
        {
            builder.Append("[").Append(RenderLimits.Printable(group.Key)).AppendLine("]");

            foreach (var entry in group)
            {
                builder.Append("- ").Append(RenderLimits.Printable(entry.Entry));

                if (!entry.Enabled)
                {
                    builder.Append(" (disabled)");
                }

                builder.Append("  ").Append(RenderLimits.Printable(entry.ImagePath) ?? "(no image recorded)");

                if (entry.ImageMissing)
                {
                    // Before the signature marker, because there is no file to have signed: an entry
                    // whose target is gone would otherwise render more quietly than a healthy one.
                    builder.Append("  [FILE NOT FOUND]");
                }

                if (entry.SignatureVerdict is "Not verified")
                {
                    builder.Append("  [UNSIGNED]");
                }
                else if (entry.Company is { } company)
                {
                    builder.Append("  ").Append(RenderLimits.Printable(company));
                }

                builder.AppendLine();
                builder.Append("    ").AppendLine(RenderLimits.Printable(entry.Location));
            }
        }

        builder.AppendLine();

        if (result.SignaturesVerified)
        {
            builder.Append(result.UnsignedCount switch
            {
                0 => "Every entry returned is validly signed.",
                1 => "1 entry is not validly signed - that is the one worth looking at first.",
                var n => $"{n} entries are not validly signed - those are worth looking at first."
            });
        }
        else
        {
            builder.Append("Signatures were not checked. Pass unsignedOnly to see only what fails " +
                           "verification, which is both faster to read and usually the point.");
        }

        if (result.MissingImageCount > 0)
        {
            builder.AppendLine().Append(result.MissingImageCount == 1
                ? "1 entry points at a file that is not there, marked [FILE NOT FOUND]. "
                : $"{result.MissingImageCount} entries point at files that are not there, marked " +
                  "[FILE NOT FOUND]. ")
                .Append("That is usually an uninstall that left its hook behind -- harmless, but it " +
                        "is also what a hijack looks like before the replacement is dropped in.");
        }

        builder.AppendLine();
        RenderLimits.NoteElision(builder, result.Entries.Count, "returned entries");

        if (result.Truncated)
        {
            builder.AppendLine().Append("Showing the first ").Append(result.Entries.Count).Append(" of ")
                .Append(result.TotalMatched.ToString("N0", CultureInfo.InvariantCulture))
                .Append("; narrow with categories or nameFilter, or raise WINDIAG_MAX_RESULTS.");
        }

        return builder.ToString().TrimEnd();
    }
}
