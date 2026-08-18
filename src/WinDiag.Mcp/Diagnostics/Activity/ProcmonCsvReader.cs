using System.Globalization;
using System.Text;
using WinDiag.Mcp.Diagnostics.External;

namespace WinDiag.Mcp.Diagnostics.Activity;

/// <summary>Streams events out of a Procmon CSV export.</summary>
/// <remarks>
/// <para>Fields are located <strong>by header name</strong>. That is the opposite of the rule
/// <c>handle.exe</c> forced, and deliberately so: Procmon's header genuinely describes its own rows —
/// verified against a real export in
/// <c>tests/WinDiag.Mcp.Tests/Fixtures/procmon-golden.csv</c>, where seven header columns line up with
/// seven row fields. Reading by name also decouples this from whichever column set the machine happens
/// to have configured, so an unexpected layout loses a field instead of silently mis-attributing every
/// field.</para>
/// <para>Streamed, never loaded: twenty seconds of unfiltered capture measured 65 MB of CSV.</para>
/// </remarks>
internal static class ProcmonCsvReader
{
    /// <summary>Results that mean something went wrong, as opposed to ordinary traffic.</summary>
    /// <remarks>
    /// An explicit set rather than "anything that is not SUCCESS". Procmon emits
    /// <c>FAST IO DISALLOWED</c> constantly as a normal fast-path rejection — it was 6 of 40 rows in the
    /// captured fixture — and <c>END OF FILE</c>, <c>BUFFER OVERFLOW</c> and <c>FILE LOCKED WITH
    /// WRITERS</c> are equally routine. Treating those as failures buries the handful of results that
    /// actually explain a bug.
    /// </remarks>
    private static readonly HashSet<string> ProblemResults = new(StringComparer.OrdinalIgnoreCase)
    {
        "ACCESS DENIED",
        "NAME NOT FOUND",
        "PATH NOT FOUND",
        "SHARING VIOLATION",
        "NAME COLLISION",
        "NAME INVALID",
        "INVALID PARAMETER",
        "PRIVILEGE NOT HELD",
        "CANNOT DELETE",
        "DISK FULL"
    };

    public static bool IsProblem(string result) => ProblemResults.Contains(result.Trim());

    /// <summary>Opens a capture CSV for streaming.</summary>
    /// <remarks>
    /// <c>detectEncodingFromByteOrderMarks</c> matters: the export carries a UTF-8 BOM, and reading it
    /// without stripping that leaves the first header cell as <c>﻿Time of Day</c>, so every
    /// by-name lookup for the first column fails while the rest appear to work.
    /// </remarks>
    public static StreamReader Open(string path) =>
        new(
            new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 64 * 1024),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            detectEncodingFromByteOrderMarks: true);

    /// <summary>Reports whether the export actually carries a column, by reading only its header.</summary>
    /// <remarks>
    /// Only the five columns every filter depends on are required (see <see cref="MapColumns"/>); the
    /// rest are optional and a missing one simply reads as empty. That is fine until something
    /// <em>filters</em> on an optional column, because every row then compares against "" and the query
    /// returns a confident zero. Callers check here first so they can say "this capture has no Detail
    /// column" instead of "nothing matched".
    /// </remarks>
    public static bool HasColumn(string path, string columnName)
    {
        using var reader = Open(path);

        foreach (var record in DelimitedText.ReadRecords(reader, CancellationToken.None))
        {
            return MapColumns(record).ContainsKey(columnName);
        }

        return false;
    }

    /// <summary>Streams events, yielding nothing rather than throwing on a malformed row.</summary>
    public static IEnumerable<ActivityEvent> Read(TextReader reader, CancellationToken cancellationToken)
    {
        Dictionary<string, int>? columns = null;

        foreach (var record in DelimitedText.ReadRecords(reader, cancellationToken))
        {
            if (columns is null)
            {
                columns = MapColumns(record);
                continue;
            }

            if (record.Count < 3)
            {
                continue;
            }

            var pidText = Field(record, columns, "PID");
            if (!int.TryParse(pidText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid))
            {
                continue;
            }

            yield return new ActivityEvent(
                Time: Field(record, columns, "Time of Day") ?? string.Empty,
                ProcessName: Field(record, columns, "Process Name") ?? string.Empty,
                ProcessId: pid,
                Operation: Field(record, columns, "Operation") ?? string.Empty,
                Path: Field(record, columns, "Path") ?? string.Empty,
                Result: Field(record, columns, "Result") ?? string.Empty,
                Detail: Field(record, columns, "Detail") ?? string.Empty);
        }
    }

    private static Dictionary<string, int> MapColumns(List<string> header)
    {
        var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < header.Count; i++)
        {
            // Trim a stray BOM defensively: BOM stripping is the reader's job, but a capture produced
            // by some other path should degrade to a working parse rather than a silent miss.
            var name = header[i].Trim().TrimStart('﻿');
            if (name.Length > 0)
            {
                map[name] = i;
            }
        }

        foreach (var required in (string[])["Process Name", "PID", "Operation", "Path", "Result"])
        {
            if (!map.ContainsKey(required))
            {
                throw new FormatException(
                    $"The capture is missing the '{required}' column, so it cannot be read. Columns " +
                    $"present: {string.Join(", ", map.Keys)}. Re-export the trace with the shipped " +
                    "Procmon configuration.");
            }
        }

        return map;
    }

    private static string? Field(List<string> record, Dictionary<string, int> columns, string name) =>
        columns.TryGetValue(name, out var index) && index < record.Count ? record[index] : null;
}
