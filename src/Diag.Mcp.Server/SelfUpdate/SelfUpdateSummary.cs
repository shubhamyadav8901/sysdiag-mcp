using System.Globalization;
using System.Text;

namespace Diag.Mcp.Server.SelfUpdate;

/// <summary>What update_self tells its caller, shared so every server words it the same.</summary>
public static class SelfUpdateSummary
{
    /// <summary>Renders the drain budget in a unit that is never zero.</summary>
    /// <remarks>
    /// Integer minutes alone reported any budget under a minute as "up to 0 minutes", and the
    /// configured range starts at 1 second.
    /// </remarks>
    private static string DescribeBudget(int seconds) =>
        seconds < 60
            ? $"{seconds.ToString(CultureInfo.InvariantCulture)} seconds"
            : $"{(seconds / 60).ToString(CultureInfo.InvariantCulture)} minutes";

    public static string Render(SelfUpdateResult result)
    {
        var builder = new StringBuilder();

        builder.Append("Accepted ").Append(RenderLimits.Printable(result.StagedPath)).Append(" (")
            .Append(result.SizeBytes.ToString("N0", CultureInfo.InvariantCulture))
            .Append(" bytes, signature ").Append(RenderLimits.Printable(result.SignatureVerdict)).AppendLine(").");

        builder.Append("SHA-256 ").AppendLine(RenderLimits.Printable(result.Sha256));
        builder.Append("Replacing ").AppendLine(RenderLimits.Printable(result.LivePath));
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
                + "It still allows itself up to 30 seconds to stop the tools it started cleanly, "
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
            .Append(RenderLimits.Printable(result.HelperLogPath));

        return builder.ToString();
    }
}
