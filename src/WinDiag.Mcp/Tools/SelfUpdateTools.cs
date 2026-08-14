using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics.SelfUpdate;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>update_self</c>.</summary>
public sealed record UpdateSelfResult(string Summary, SelfUpdateResult Update);

/// <summary>Replacing the server's own binary. Registered only when explicitly enabled.</summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class SelfUpdateTools
{
    private readonly ISelfUpdater _updater;

    public SelfUpdateTools(ISelfUpdater updater)
    {
        _updater = updater;
    }

    [McpServerTool(
        Name = "update_self",
        Title = "Install a staged server build",
        ReadOnly = false,
        Destructive = true,
        Idempotent = false,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Replace this server's own executable with a build already copied next to it, then restart. " +
        "Use it to update a target reachable by file copy but not by remote execution, where the running " +
        "process would otherwise have to be stopped by hand at the console. " +
        "You must pass the SHA-256 you expect; anything else is refused and nothing is changed. " +
        "On success the server exits within a few seconds and comes back on the same address, so THIS " +
        "CONNECTION WILL DROP - that is success, not failure. Wait a few seconds, reconnect, and check " +
        "the version. If it does not come back, read the helper log named in the result.")]
    public UpdateSelfResult UpdateSelf(
        [Description("SHA-256 of the staged build, as reported by file_signatures on the staged file")]
        string expectedSha256,
        [Description("Name of the staged file beside the server. Must be a file name, not a path.")]
        string stagedFileName = "WinDiag.Mcp.new.exe",
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedSha256);

        var result = _updater.Update(expectedSha256, stagedFileName, cancellationToken);

        return new UpdateSelfResult(Render(result), result);
    }

    internal static string Render(SelfUpdateResult result)
    {
        var builder = new StringBuilder();

        builder.Append("Accepted ").Append(result.StagedPath).Append(" (")
            .Append(result.SizeBytes.ToString("N0", CultureInfo.InvariantCulture))
            .Append(" bytes, signature ").Append(result.SignatureVerdict).AppendLine(").");

        builder.Append("SHA-256 ").AppendLine(result.Sha256);
        builder.Append("Replacing ").AppendLine(result.LivePath);
        builder.AppendLine();

        // Said plainly because the caller is about to see a dropped connection and must not read it as
        // a failure and retry into a half-finished swap.
        builder.AppendLine(
            "This server is shutting down now and will be restarted by a helper with the same arguments. " +
            "THE CONNECTION WILL DROP - that is expected. Wait about ten seconds and reconnect.");
        builder.Append("If it does not come back, the helper logged what happened to ")
            .Append(result.HelperLogPath);

        return builder.ToString();
    }
}
