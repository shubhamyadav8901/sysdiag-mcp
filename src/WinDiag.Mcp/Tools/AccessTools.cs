using System.ComponentModel;
using System.Runtime.Versioning;
using System.Text;
using Diag.Mcp.Server.Files;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.Access;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>effective_access</c>.</summary>
public sealed record EffectiveAccessResult(string Summary, AccessReport Report);

/// <summary>Why is this denied.</summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class AccessTools
{
    private readonly IAccessInspector _access;
    private readonly FileTransferOptions _files;

    public AccessTools(IAccessInspector access, FileTransferOptions files)
    {
        _access = access;
        _files = files;
    }

    [McpServerTool(
        Name = "effective_access",
        Title = "Why is this access denied",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Explain the permissions on a file, folder or registry key: the owner, every access control " +
        "entry with deny rules listed first, and - crucially - the result of actually attempting the " +
        "access rather than only reasoning about the ACL. Use it for 'access denied' reports, for " +
        @"'the service cannot write its log', or to check who can modify a key. Registry paths use " +
        @"HKLM\, HKCU\, HKCR\ or HKU\ prefixes.")]
    public EffectiveAccessResult EffectiveAccess(
        [Description(@"File path, folder path, or registry key such as HKLM\SOFTWARE\Vendor\Product")]
        string path,
        [Description("Optional account to highlight, for example 'NETWORK SERVICE' or 'CONTOSO\\svc-app'")]
        string? account = null,
        [Description("Also test write access. Acquires a write handle without modifying the file. Files only.")]
        bool probeWrite = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!RegistryPath.IsRegistryPath(path))
        {
            LocalPathGuard.RequireLocal(path, nameof(path), _files);
        }

        var report = _access.Inspect(path, account, probeWrite, cancellationToken);
        return new EffectiveAccessResult(Render(report), report);
    }

    internal static string Render(AccessReport report)
    {
        var builder = new StringBuilder();

        builder.Append(report.Kind).Append(": ").AppendLine(RenderLimits.Printable(report.Path));
        builder.Append("Owner: ").AppendLine(RenderLimits.Printable(report.Owner) ?? "(could not be read)");

        // Lead with the empirical result. It is the answer; the ACL below is the explanation.
        builder.Append("As ").Append(RenderLimits.Printable(report.ProbeIdentity)).Append(": read=")
            .Append(Describe(report.Probe.CanRead));

        if (report.Probe.CanWrite is { } canWrite)
        {
            builder.Append(", write=").Append(Describe(canWrite));
        }

        builder.AppendLine();

        if (report.Probe.ReadError is { } readError)
        {
            builder.Append("  Read failed: ").AppendLine(RenderLimits.Printable(readError));
        }

        if (report.Probe.WriteError is { } writeError)
        {
            builder.Append("  ").AppendLine(RenderLimits.Printable(writeError));
        }

        if (report.Account is { } account)
        {
            builder.Append("Entries naming '").Append(RenderLimits.Printable(account)).Append("': ");

            if (report.RulesForAccount.Count == 0)
            {
                builder.AppendLine("none.");
            }
            else
            {
                builder.AppendLine();
                foreach (var rule in report.RulesForAccount)
                {
                    AppendRule(builder, rule);
                }
            }

            // Stated rather than implied: an ACL listing is not an effective-rights calculation, and
            // pretending otherwise would produce confident wrong answers about group-granted access.
            builder.AppendLine(
                "NOTE: these are entries that name the account directly. Rights granted through group " +
                "membership are not resolved here, so an account with no entries above may still have " +
                "access via a group such as Users or Administrators.");
        }

        builder.Append("Access control entries (deny first, deny always wins):").AppendLine();
        foreach (var rule in report.Rules)
        {
            AppendRule(builder, rule);
        }

        return builder.ToString().TrimEnd();
    }

    private static void AppendRule(StringBuilder builder, AccessRule rule)
    {
        builder.Append("- ").Append(RenderLimits.Printable(rule.Type.ToUpperInvariant())).Append(' ')
            .Append(RenderLimits.Printable(rule.Identity)).Append(": ").Append(RenderLimits.Printable(rule.Rights));

        if (rule.Inherited)
        {
            builder.Append(" (inherited)");
        }

        builder.AppendLine();
    }

    private static string Describe(bool? value) => value switch
    {
        true => "YES",
        false => "DENIED",
        null => "not tested"
    };
}
