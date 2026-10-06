using System.Globalization;
using WinDiag.Mcp.Diagnostics.External;

namespace WinDiag.Mcp.Diagnostics.Autostart;

/// <summary>Parses the CSV that <c>autorunsc -c -t</c> writes.</summary>
/// <remarks>
/// <para>Mapped <strong>by header name</strong>, the opposite of <see cref="Handles.HandleCsvParser"/>
/// and for the opposite reason: Autoruns' header genuinely describes its rows. Verified against
/// autorunsc 14.3, where an <c>-a lt</c> capture produced 255 lines that every one parsed to exactly
/// the 11 advertised fields. Mapping by name also means a column set that differs between Autoruns
/// versions degrades to "a field is missing" rather than to silent mis-attribution.</para>
/// <para>Two things about this output cost time if they are not known:</para>
/// <list type="bullet">
/// <item><description>It is <strong>UTF-16 LE with a BOM</strong>, where every other console tool
/// here writes console text. Handled in <c>ExternalToolPolicy.UnicodeConsoleTool</c>, not here.</description></item>
/// <item><description>A row whose <c>Entry</c> is empty is a <strong>section header</strong> — Autoruns
/// emits one for every location it examined, including the ones that were empty. In a 254-row capture,
/// 15 were these. Reported as entries they would read as autostarts with no name and no image. Only a
/// row that is otherwise empty too is taken for one; see <see cref="IsSectionHeader"/>.</description></item>
/// </list>
/// </remarks>
internal static class AutorunscCsvParser
{
    private const string TimeColumn = "Time";
    private const string LocationColumn = "Entry Location";
    private const string EntryColumn = "Entry";
    private const string EnabledColumn = "Enabled";
    private const string CategoryColumn = "Category";
    private const string ProfileColumn = "Profile";
    private const string DescriptionColumn = "Description";
    private const string CompanyColumn = "Company";

    /// <summary>
    /// Only present when <c>-s</c> was passed — Autoruns inserts it, it is not always there.
    /// </summary>
    /// <remarks>
    /// This is the reason to map by name. Verified against 14.3: without <c>-s</c> the header is 11
    /// columns, and with it 12, because Signer is inserted <em>between</em> Description and Company.
    /// Anything reading Company by position would read the signer for one invocation and the publisher
    /// for the other, with nothing in the output to say which.
    /// </remarks>
    private const string SignerColumn = "Signer";
    private const string ImagePathColumn = "Image Path";
    private const string VersionColumn = "Version";
    private const string LaunchStringColumn = "Launch String";

    /// <summary>Columns without which the result would not answer the question the tool exists for.</summary>
    private static readonly string[] Required =
        [LocationColumn, EntryColumn, CategoryColumn, ImagePathColumn];

    /// <summary>What Autoruns writes into the image column when the entry points at nothing.</summary>
    private const string FileNotFoundPrefix = "File not found:";

    private const string VerifiedPrefix = "(Verified)";
    private const string NotVerifiedPrefix = "(Not verified)";

    /// <summary>Reads autorunsc's output into entries, counting the records that did not fit.</summary>
    /// <remarks>
    /// <para>Records are read quote-aware, so a quoted field may span lines. Splitting on <c>'\n'</c> first
    /// is what this replaced, and it was exploitable: a Run value name is any text an unprivileged user
    /// likes, including a line break followed by a complete row. Split by line, the real record's first
    /// fragment ended in an open quote, read as a section header and was dropped -- the unsigned entry
    /// disappeared -- and the smuggled row was reported as a signed Microsoft entry.</para>
    /// <para>Only the lines <em>before</em> the header are still read one at a time. autorunsc writes
    /// notes there, and a stray quote in one of them must not swallow the header.</para>
    /// </remarks>
    public static AutorunscParseResult Parse(string csv)
    {
        var entries = new List<AutostartEntry>();

        if (string.IsNullOrWhiteSpace(csv))
        {
            return new AutorunscParseResult(entries, 0);
        }

        var (columns, headerWidth, body) = FindHeader(csv);
        var malformed = 0;

        foreach (var fields in DelimitedText.ReadRecords(new StringReader(body), CancellationToken.None))
        {
            if (fields.Count == 1 && fields[0].Trim().Length == 0)
            {
                continue;
            }

            // A record whose width differs from the header's is not one autorunsc wrote whole: it is a
            // fragment of a record broken by an unquoted line break, or several run together. Either
            // way no column of it can be trusted, and neither can the list it came from -- so it is
            // counted for the caller rather than dropped or guessed at.
            if (fields.Count != headerWidth)
            {
                malformed++;
                continue;
            }

            switch (ReadRow(fields, columns))
            {
                case { } entry:
                    entries.Add(entry);
                    break;
                case null when !IsSectionHeader(fields, columns):
                    malformed++;
                    break;
            }
        }

        return new AutorunscParseResult(entries, malformed);
    }

    /// <summary>Finds the header line and returns everything after it.</summary>
    private static (Dictionary<string, int> Columns, int Width, string Body) FindHeader(string csv)
    {
        var position = 0;

        while (position < csv.Length)
        {
            var end = csv.IndexOf('\n', position);
            var next = end < 0 ? csv.Length : end + 1;
            var line = csv[position..(end < 0 ? csv.Length : end)].TrimEnd('\r');

            if (line.Length > 0)
            {
                var fields = DelimitedLine.Split(line);
                if (LooksLikeHeader(fields))
                {
                    return (MapColumns(fields), fields.Count, csv[next..]);
                }
            }

            // Autoruns writes progress and access-denied notes to stdout ahead of the header.
            position = next;
        }

        throw new FormatException(
            "autorunsc produced no recognisable CSV header. Expected a line naming at least " +
            $"{string.Join(", ", Required)}. This usually means the output was decoded with the " +
            "wrong encoding -- autorunsc writes UTF-16 -- or that its column set has changed.");
    }

    /// <summary>
    /// True for the row Autoruns writes for a location it examined: a place, and nothing found in it.
    /// </summary>
    /// <remarks>
    /// An empty Entry alone is not enough. The captured section headers carry Time, Location, Category
    /// and Profile and nothing else; a row with an empty Entry that still names an image, a signer or a
    /// launch string is something else, and treating it as a header is how a real autostart was hidden.
    /// </remarks>
    private static bool IsSectionHeader(List<string> fields, Dictionary<string, int> columns) =>
        new[]
        {
            EntryColumn, EnabledColumn, DescriptionColumn, SignerColumn, CompanyColumn,
            ImagePathColumn, VersionColumn, LaunchStringColumn
        }.All(name => Field(fields, columns, name) is null);

    private static bool LooksLikeHeader(List<string> fields) =>
        fields.Any(f => string.Equals(f.Trim(), EntryColumn, StringComparison.OrdinalIgnoreCase))
        && fields.Any(f => string.Equals(f.Trim(), LocationColumn, StringComparison.OrdinalIgnoreCase));

    private static Dictionary<string, int> MapColumns(List<string> header)
    {
        var columns = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < header.Count; i++)
        {
            columns[header[i].Trim()] = i;
        }

        var missing = Required.Where(name => !columns.ContainsKey(name)).ToArray();

        if (missing.Length > 0)
        {
            // Loudly, per the same rule the Procmon parser follows: a missing column silently read as
            // empty turns "this entry has no image on disk" -- a real finding -- into noise.
            throw new FormatException(
                $"autorunsc CSV is missing the {string.Join(", ", missing)} column(s). Its output " +
                $"format has changed; this parser was written against 14.3. Header was: " +
                string.Join(", ", header.Select(h => h.Trim())));
        }

        return columns;
    }

    private static AutostartEntry? ReadRow(List<string> fields, Dictionary<string, int> columns)
    {
        var entry = Field(fields, columns, EntryColumn);

        if (string.IsNullOrWhiteSpace(entry))
        {
            // Not an autostart: a section header, or -- when IsSectionHeader says otherwise -- a row the
            // caller counts as malformed.
            return null;
        }

        // Signer when -s was passed, Company otherwise. On a verified row Autoruns writes the same
        // prefixed value into both; on an unverified one Company holds a "(Not Verified)" placeholder
        // rather than a publisher, which is why the publisher is taken from whichever field was parsed.
        var (verdict, signer) = SplitVerdict(
            Field(fields, columns, SignerColumn) ?? Field(fields, columns, CompanyColumn));

        var (image, missing) = SplitImagePath(Field(fields, columns, ImagePathColumn));

        return new AutostartEntry(
            Category: Field(fields, columns, CategoryColumn) ?? "(unknown)",
            Location: Field(fields, columns, LocationColumn) ?? "(unknown)",
            Entry: entry!,

            // Autoruns writes "enabled"/"disabled"; anything else is treated as enabled rather than
            // hidden, because dropping an entry over an unrecognised word is the worse failure.
            Enabled: !string.Equals(
                Field(fields, columns, EnabledColumn), "disabled", StringComparison.OrdinalIgnoreCase),
            Profile: Field(fields, columns, ProfileColumn),
            Description: Field(fields, columns, DescriptionColumn),
            Company: signer,
            ImagePath: image,
            Version: Field(fields, columns, VersionColumn),
            LaunchString: Field(fields, columns, LaunchStringColumn),
            SignatureVerdict: verdict,
            Timestamp: ParseTimestamp(Field(fields, columns, TimeColumn)),
            ImageMissing: missing);
    }

    /// <summary>Separates "the file is not there" from the path it is not there at.</summary>
    /// <remarks>
    /// Autoruns signals a broken entry by writing <c>File not found: atmfd.dll</c> into the image
    /// column rather than by leaving it empty. Left as-is that is prose in a path field: no filter
    /// matches it, no signature verdict attaches to it, and the entry renders more quietly than a
    /// healthy one -- which is exactly backwards, because a hook pointing at nothing is a finding.
    /// </remarks>
    internal static (string? Path, bool Missing) SplitImagePath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return (null, false);
        }

        var text = value.Trim();

        if (!text.StartsWith(FileNotFoundPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return (text, false);
        }

        var remainder = text[FileNotFoundPrefix.Length..].Trim();

        return (remainder.Length == 0 ? null : remainder, true);
    }

    /// <summary>Separates Autoruns' signature verdict from the publisher name it is prefixed to.</summary>
    /// <remarks>
    /// Observed values, autorunsc 14.3 with <c>-s</c>:
    /// <code>
    /// (Verified) Microsoft Windows
    /// (Verified) Contoso Ltd
    /// (Not verified) (Not Verified)
    /// </code>
    /// The last is not a publisher called "(Not Verified)" -- it is the unsigned placeholder Autoruns
    /// already wrote into Company, prefixed a second time. Returned as a publisher it would appear in
    /// a report as though something had been signed by it.
    /// </remarks>
    internal static (string? Verdict, string? Signer) SplitVerdict(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return (null, null);
        }

        var text = value.Trim();

        if (text.StartsWith(VerifiedPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return ("Verified", Publisher(text[VerifiedPrefix.Length..]));
        }

        if (text.StartsWith(NotVerifiedPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return ("Not verified", Publisher(text[NotVerifiedPrefix.Length..]));
        }

        return (null, Publisher(text));
    }

    private static string? Publisher(string value)
    {
        var trimmed = value.Trim();

        return trimmed.Length == 0
               || trimmed.Equals("(Not Verified)", StringComparison.OrdinalIgnoreCase)
            ? null
            : trimmed;
    }

    /// <summary>Reads the normalised UTC stamp produced by <c>-t</c>.</summary>
    /// <remarks>
    /// <c>-t</c> is always passed, because the default is a locale-formatted local time -- an
    /// observed capture wrote "01-04-2024 12:56:32", which is either 1 April or 4 January depending on
    /// the machine's settings, and nothing in the output says which.
    /// </remarks>
    internal static DateTimeOffset? ParseTimestamp(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return DateTimeOffset.TryParseExact(
            value.Trim(),
            "yyyyMMdd-HHmmss",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var parsed)
            ? parsed
            : null;
    }

    private static string? Field(List<string> fields, Dictionary<string, int> columns, string name) =>
        columns.TryGetValue(name, out var index) && index < fields.Count
            ? NullIfEmpty(fields[index])
            : null;

    private static string? NullIfEmpty(string value)
    {
        var trimmed = value.Trim();
        return trimmed.Length == 0 ? null : trimmed;
    }
}

/// <summary>What one run of autorunsc parsed to.</summary>
/// <param name="MalformedRows">
/// Records after the header that were not reported: a width other than the header's, or an empty Entry
/// on a row that is not a section header. Non-zero means the list cannot be taken as complete.
/// </param>
internal sealed record AutorunscParseResult(List<AutostartEntry> Entries, int MalformedRows);
