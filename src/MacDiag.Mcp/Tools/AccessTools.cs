using System.ComponentModel;
using System.Text;
using MacDiag.Mcp.Diagnostics.Access;
using ModelContextProtocol.Server;

namespace MacDiag.Mcp.Tools;

/// <summary>Structured result of <c>effective_access</c>.</summary>
public sealed record EffectiveAccessResult(string Summary, EffectiveAccessReport Report);

[McpServerToolType]
public sealed class AccessTools(IAccessInspector access)
{
    [McpServerTool(
        Name = "effective_access",
        Title = "Why is this access denied",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Explain whether an account or a running process can read, write and execute a file or directory. The " +
        "decision is the kernel's own answer - access(2) through /bin/test run as that account - so ACLs, nested " +
        "groups and file flags are applied exactly as macOS applies them. Shown alongside it: the mode, ACL entries " +
        "(a deny entry that applies is named), file flags (uchg, schg, restricted), the mount and its options, and " +
        "the first directory on the way the subject cannot search. Give account (a user name or uid) or processId " +
        "(evaluated as that process's user). Asking on behalf of another account needs the server to run as root; " +
        "without it that answer is reported as not evaluated. System Integrity Protection and privacy (TCC) " +
        "protections are named, not evaluated.")]
    public async Task<EffectiveAccessResult> EffectiveAccess(
        [Description("Full path of the file or directory")] string path,
        [Description("The account to evaluate: a user name or numeric uid. Give this or processId.")] string? account = null,
        [Description("A running process whose user to evaluate. Give this or account.")] int? processId = null,
        CancellationToken cancellationToken = default)
    {
        var report = await access.InspectAsync(path, account, processId, cancellationToken).ConfigureAwait(false);
        return new EffectiveAccessResult(Render(report), report);
    }

    internal static string Render(EffectiveAccessReport report)
    {
        static string Verdict(bool? allowed) => allowed switch { true => "allowed", false => "DENIED", null => "not evaluated" };
        static string YesNo(bool? value) => value switch { true => "yes", false => "no", null => "?" };

        var builder = new StringBuilder();
        builder.Append(RenderLimits.Printable(report.Subject.Description)).Append(" on ").Append(RenderLimits.Printable(report.Path))
            .Append(" (").Append(RenderLimits.Printable(report.Kind)).AppendLine(")");
        if (report.ResolvedPath is { } resolved)
        {
            builder.Append("  resolves to ").AppendLine(RenderLimits.Printable(resolved));
        }

        builder.Append("Read:    ").Append(Verdict(report.Read.Allowed)).Append(" - ").AppendLine(RenderLimits.Printable(report.Read.Reason));
        builder.Append("Write:   ").Append(Verdict(report.Write.Allowed)).Append(" - ").AppendLine(RenderLimits.Printable(report.Write.Reason));
        builder.Append("Execute: ").Append(Verdict(report.Execute.Allowed)).Append(" - ").AppendLine(RenderLimits.Printable(report.Execute.Reason));
        if (report.BlockedAt is { } blockedAt)
        {
            // The inspector takes BlockedAt from a traversal step, but the summary is the one place the caller sees
            // the verdict: a report that broke that pairing must still render, not throw instead of answering.
            builder.Append("BLOCKED at ").Append(RenderLimits.Printable(blockedAt));
            if (report.Traversal.FirstOrDefault(s => s.Path == blockedAt) is { } step)
            {
                builder.Append(": ").Append(RenderLimits.Printable(step.Reason));
            }

            builder.AppendLine();
        }

        builder.Append("Owner ").Append(RenderLimits.Printable(report.Owner)).Append(", group ").Append(RenderLimits.Printable(report.Group))
            .Append(", mode ").AppendLine(RenderLimits.Printable(report.Mode));
        if (report.Flags.Count > 0)
        {
            builder.Append("Flags: ").AppendLine(RenderLimits.Printable(string.Join(", ", report.Flags)));
        }

        foreach (var entry in report.Acl)
        {
            builder.Append("ACL: ").AppendLine(RenderLimits.Printable(entry));
        }

        if (report.MountPoint is { } mountPoint)
        {
            builder.Append("Mounted at ").Append(RenderLimits.Printable(mountPoint)).Append(" (")
                .Append(RenderLimits.Printable(string.Join(", ", report.MountOptions))).AppendLine(")");
        }

        builder.Append("The server (uid ").Append(report.Probe.UserId).Append(") itself: read ").Append(YesNo(report.Probe.Read))
            .Append(", write ").Append(YesNo(report.Probe.Write)).Append(", execute ").Append(YesNo(report.Probe.Execute)).AppendLine();
        foreach (var note in report.Notes)
        {
            builder.Append("NOTE: ").AppendLine(RenderLimits.Printable(note));
        }

        return builder.ToString().TrimEnd();
    }
}
