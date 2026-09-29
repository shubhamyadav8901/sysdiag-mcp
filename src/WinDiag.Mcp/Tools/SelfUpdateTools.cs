using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using ModelContextProtocol.Server;
using Diag.Mcp.Server.SelfUpdate;
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
        "By default the server FINISHES whatever tool calls are already running before it restarts, " +
        "refusing new calls meanwhile - so on a busy target this can take minutes, and the refusals are " +
        "how you know the old process is still draining. Pass force to skip that and cut running calls " +
        "off instead - and you can still change your mind, because update_self is the one tool a " +
        "draining server keeps accepting: call it again with force to stop waiting and restart now. " +
        "Either way THIS CONNECTION WILL DROP - that is success, not failure. Reconnect " +
        "and check the version; if it does not come back, read the helper log named in the result.")]
    public UpdateSelfResult UpdateSelf(
        [Description("SHA-256 of the staged build, as reported by file_signatures on the staged file")]
        string expectedSha256,
        [Description("Name of the staged file beside the server. Must be a file name, not a path.")]
        string stagedFileName = "WinDiag.Mcp.new.exe",
        [Description(
            "Set true to restart without waiting for running tool calls. Their work is cut off "
            + "mid-answer and anything they were writing - a capture, a dump - is left partial and "
            + "orphaned. Default false, which waits.")]
        bool force = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedSha256);

        SelfUpdateResult result;
        try
        {
            result = _updater.Update(expectedSha256, stagedFileName, force, cancellationToken);
        }
        catch (Exception ex) when (ex is not SelfUpdateRejectedException and not ArgumentException)
        {
            // The whole call, not just part of it. Anything unexpected here would otherwise reach the
            // caller as "An error occurred invoking 'update_self'." -- and this is the tool where that
            // is least affordable, because the caller cannot tell whether the binary was replaced, the
            // server is about to exit, or nothing happened at all. Naming the type turns an afternoon
            // of bisecting into one line.
            throw new SelfUpdateRejectedException(
                $"update_self failed unexpectedly: {ex.GetType().FullName}: {ex.Message} If the server "
                + "is still answering, nothing was installed.");
        }

        return new UpdateSelfResult(Render(result), result);
    }

    internal static string Render(SelfUpdateResult result) => SelfUpdateSummary.Render(result);
}
