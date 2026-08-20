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

        var result = _updater.Update(expectedSha256, stagedFileName, force, cancellationToken);

        return new UpdateSelfResult(Render(result), result);
    }

    /// <summary>Renders the drain budget in a unit that is never zero.</summary>
    /// <remarks>
    /// Integer minutes alone reported any budget under a minute as "up to 0 minutes", and the
    /// configured range starts at 1 second.
    /// </remarks>
    private static string DescribeBudget(int seconds) =>
        seconds < 60
            ? $"{seconds.ToString(CultureInfo.InvariantCulture)} seconds"
            : $"{(seconds / 60).ToString(CultureInfo.InvariantCulture)} minutes";

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
        // a failure and retry into a half-finished swap. All three branches are future tense: this is
        // written before the wait even starts, so none of them can claim how it went.
        if (result.Forced)
        {
            builder.AppendLine(
                "force=true: this server is shutting down WITHOUT waiting. "
                + (result.OtherCallsInFlight == 0
                    ? "Nothing else was running, so nothing is lost. "
                    : $"The {result.OtherCallsInFlight} other call(s) still running are cut off and "
                      + "anything they were writing - a capture, a dump - is left partial and orphaned. ")
                + "It still allows itself up to 30 seconds to stop child tools such as Procmon cleanly, "
                + "so exit is not instant.");
        }
        else if (result.OtherCallsInFlight == 0)
        {
            builder.AppendLine(
                "Nothing else is running, so this server exits in about 3 seconds and is restarted by a "
                + "helper with the same arguments. THE CONNECTION WILL DROP - that is expected. Wait "
                + "about ten seconds and reconnect.");
        }
        else
        {
            builder.AppendLine(
                $"{result.OtherCallsInFlight} other tool call(s) are still running. This server will let "
                + $"them finish (up to {DescribeBudget(result.DrainTimeoutSeconds)}), refusing every new "
                + "call meanwhile, and only then exit and restart. THE CONNECTION WILL DROP - that is "
                + "expected. Reconnect once calls stop being refused: that refusal comes from the OLD "
                + "process, so it stopping is how you know the new build is up. If you would rather not "
                + "wait, call update_self again with force - it is the one tool still accepted while "
                + "this is pending.");
        }

        builder.Append("If it does not come back, the helper logged what happened to ")
            .Append(result.HelperLogPath);

        return builder.ToString();
    }
}
