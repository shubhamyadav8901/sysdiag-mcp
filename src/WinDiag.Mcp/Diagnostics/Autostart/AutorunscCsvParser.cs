using System.Globalization;

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
/// 15 were these. Reported as entries they would read as autostarts with no name and no image.</description></item>
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

    public static List<AutostartEntry> Parse(string csv)
    {
        var entries = new List<AutostartEntry>();

        if (string.IsNullOrWhiteSpace(csv))
        {
            return entries;
        }

        Dictionary<string, int>? columns = null;

        foreach (var line in csv.Split('\n'))
        {
            var trimmed = line.TrimEnd('\r');
            if (trimmed.Length == 0)
            {
                continue;
            }

            var fields = DelimitedLine.Split(trimmed);

            if (columns is null)
            {
                if (!LooksLikeHeader(fields))
                {
                    // Autoruns writes progress and access-denied notes to stdout ahead of the header.
                    continue;
                }

                columns = MapColumns(fields);
                continue;
            }

            var entry = ReadRow(fields, columns);
            if (entry is not null)
            {
                entries.Add(entry);
            }
        }

        if (columns is null)
        {
            throw new FormatException(
                "autorunsc produced no recognisable CSV header. Expected a line naming at least " +
                $"{string.Join(", ", Required)}. This usually means the output was decoded with the " +
                "wrong encoding -- autorunsc writes UTF-16 -- or that its column set has changed.");
        }

        return entries;
    }

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
            // A section header for a location Autoruns looked at. Not an autostart.
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
