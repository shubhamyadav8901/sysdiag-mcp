using System.Globalization;
using System.Text;

namespace Diag.Mcp.Server;

/// <summary>
/// How much of a result is worth writing into the human-readable summary.
/// </summary>
/// <remarks>
/// <para>Deliberately <strong>not</strong> tied to a server's <c>…_MAX_RESULTS</c> setting. That cap answers "how many
/// rows should this tool return", and it is set high so handle-heavy tools are not truncated. This one
/// answers a different question -- "how many rows are worth prose" -- and the two must not move
/// together: at a 50,000 row cap a summary that renders every row builds a single contiguous string of
/// tens of megabytes, which is a real allocation failure on the win-x86 build and swamps the reader's
/// context either way.</para>
/// <para>The rows themselves are never dropped. They are all in the structured content, which is what a
/// caller filters and counts on; only the prose is abbreviated, and it says so.</para>
/// </remarks>
public static class RenderLimits
{
    /// <summary>Rows rendered into a summary, however many the structured result carries.</summary>
    public const int MaxRenderedRows = 200;

    /// <summary>Longest single joined list (subkey names and the like) written into a summary.</summary>
    public const int MaxJoinedItems = 100;

    /// <summary>Notes that the prose showed fewer rows than the result holds, naming both counts.</summary>
    public static void NoteElision(StringBuilder builder, int total, string noun)
    {
        if (total <= MaxRenderedRows)
        {
            return;
        }

        builder.Append("Summary lists the first ").Append(Format(MaxRenderedRows))
            .Append(" of ").Append(Format(total)).Append(' ').Append(noun)
            .AppendLine("; every one is in this result's structured content.");
    }

    /// <summary>Joins a list for prose, eliding the tail rather than emitting one enormous line.</summary>
    public static string Join(IReadOnlyCollection<string> items)
    {
        if (items.Count <= MaxJoinedItems)
        {
            return string.Join(", ", items);
        }

        return string.Join(", ", items.Take(MaxJoinedItems))
               + $", … and {Format(items.Count - MaxJoinedItems)} more (all in the structured content)";
    }

    private static string Format(int value) => value.ToString("N0", CultureInfo.InvariantCulture);
}
