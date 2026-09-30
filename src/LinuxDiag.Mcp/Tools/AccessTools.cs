using System.ComponentModel;
using System.Text;
using LinuxDiag.Mcp.Diagnostics.Access;
using ModelContextProtocol.Server;

namespace LinuxDiag.Mcp.Tools;

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
        "Explain whether an account or a running process can read, write and execute a file or directory, and which " +
        "rule decides: owner, group or other bits, a POSIX ACL entry and its mask, CAP_DAC_OVERRIDE, a read-only or " +
        "noexec mount, an immutable file, or a directory on the way it cannot search. Give account (a user name or " +
        "uid; groups from the account database) or processId (that process's credentials as they are now). Also " +
        "shows the ACL, default ACL, file capabilities and mount, and the kernel's own answer for the server's " +
        "credentials, which exposes AppArmor, SELinux and filesystem-specific denials when the subject is the server " +
        "itself. AppArmor and SELinux policy is not evaluated for anyone else.")]
    public EffectiveAccessResult EffectiveAccess(
        [Description("Full path of the file or directory")] string path,
        [Description("The account to evaluate: a user name or numeric uid. Give this or processId.")] string? account = null,
        [Description("A running process whose uid, groups and capabilities to evaluate. Give this or account.")] int? processId = null)
    {
        var report = access.Inspect(path, account, processId);
        return new EffectiveAccessResult(Render(report), report);
    }

    internal static string Render(EffectiveAccessReport report)
    {
        static string Verdict(bool allowed) => allowed ? "allowed" : "DENIED";
        static string YesNo(bool value) => value ? "yes" : "no";

        var builder = new StringBuilder();
        builder.Append(report.Subject.Description).Append(" on ").Append(report.Path).Append(" (").Append(report.Kind).AppendLine(")");
        if (report.ResolvedPath is { } resolved)
        {
            builder.Append("  resolves to ").AppendLine(resolved);
        }

        builder.Append("Read:    ").Append(Verdict(report.Read.Allowed)).Append(" - ").AppendLine(report.Read.Reason);
        builder.Append("Write:   ").Append(Verdict(report.Write.Allowed)).Append(" - ").AppendLine(report.Write.Reason);
        builder.Append("Execute: ").Append(Verdict(report.Execute.Allowed)).Append(" - ").AppendLine(report.Execute.Reason);
        if (report.BlockedAt is { } blockedAt)
        {
            builder.Append("BLOCKED at ").Append(blockedAt).Append(": ")
                .AppendLine(report.Traversal.First(s => s.Path == blockedAt).Reason);
        }

        builder.Append("Owner ").Append(report.Owner).Append(", group ").Append(report.Group).Append(", mode ").AppendLine(report.Mode);
        if (report.Immutable) builder.AppendLine("Immutable (chattr +i).");
        if (report.Acl.Count > 0) builder.Append("ACL: ").AppendLine(string.Join(", ", report.Acl));
        if (report.DefaultAcl.Count > 0) builder.Append("Default ACL: ").AppendLine(string.Join(", ", report.DefaultAcl));
        if (report.FileCapabilities is { } capabilities) builder.Append("Capabilities when executed: ").AppendLine(capabilities);
        if (report.MountPoint is { } mountPoint)
        {
            builder.Append("Mount: ").Append(mountPoint).Append(' ').AppendLine(string.Join(',', report.MountOptions));
        }

        builder.Append("Path: ").AppendLine(string.Join(", ", report.Traversal.Select(s => $"{s.Path} {(s.CanSearch ? "ok" : "BLOCKED")}")));
        builder.Append("Server's own kernel check (uid ").Append(report.Probe.UserId).Append("): read ").Append(YesNo(report.Probe.Read))
            .Append(", write ").Append(YesNo(report.Probe.Write)).Append(", execute ").AppendLine(YesNo(report.Probe.Execute));
        foreach (var note in report.Notes)
        {
            builder.Append("Note: ").AppendLine(note);
        }

        return builder.ToString().TrimEnd();
    }
}
