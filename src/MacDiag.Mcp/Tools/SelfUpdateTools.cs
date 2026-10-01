using System.ComponentModel;
using Diag.Mcp.Server.SelfUpdate;
using ModelContextProtocol.Server;

namespace MacDiag.Mcp.Tools;

/// <summary>Structured result of <c>update_self</c>.</summary>
public sealed record UpdateSelfResult(string Summary, SelfUpdateResult Update);

/// <summary>Replacing the server's own binary. Registered only when explicitly enabled.</summary>
[McpServerToolType]
public sealed class SelfUpdateTools(ISelfUpdater updater)
{
    [McpServerTool(
        Name = "update_self",
        Title = "Install a staged server build",
        ReadOnly = false,
        Destructive = true,
        Idempotent = false,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Replace this server's own executable with a build already copied next to it (with put_file), " +
        "then restart it through launchd. You must pass the SHA-256 you expect; anything else is refused and " +
        "nothing is changed. The staged file must be a macOS executable for this Mac (an arm64 build must be " +
        "signed; ad hoc is enough). By default the server FINISHES whatever tool calls are already running " +
        "before it restarts, refusing new calls meanwhile; pass force to cut them off instead, and call " +
        "update_self again with force to stop waiting. Either way THIS CONNECTION WILL DROP - that is success, " +
        "not failure. Reconnect and check the version; if it does not come back, read the helper log named in " +
        "the result - a build that does not come up is rolled back. Full Disk Access is tied to the code " +
        "signature, so an ad-hoc build loses it after the update; capabilities shows whether it is still granted.")]
    public UpdateSelfResult UpdateSelf(
        [Description("SHA-256 of the staged build, as put_file or push_file reported it")]
        string expectedSha256,
        [Description("Name of the staged file beside the server. Must be a file name, not a path.")]
        string stagedFileName = "MacDiag.Mcp.new",
        [Description("Set true to restart without waiting for running tool calls; their work is cut off. Default false, which waits.")]
        bool force = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedSha256);

        SelfUpdateResult result;
        try
        {
            result = updater.Update(expectedSha256, stagedFileName, force, cancellationToken);
        }
        catch (Exception ex) when (ex is not SelfUpdateRejectedException and not ArgumentException)
        {
            // Named, because on this tool "an error occurred" leaves the caller unable to tell whether the binary
            // was replaced, the server is about to exit, or nothing happened.
            throw new SelfUpdateRejectedException(
                $"update_self failed unexpectedly: {ex.GetType().FullName}: {ex.Message} If the server " +
                "is still answering, nothing was installed.");
        }

        return new UpdateSelfResult(SelfUpdateSummary.Render(result), result);
    }
}
