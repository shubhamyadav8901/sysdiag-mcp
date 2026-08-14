using System.Globalization;

namespace WinDiag.Mcp.Diagnostics.Handles;

/// <summary>Parses the CSV that <c>handle.exe -u -v</c> writes, in either of its two layouts.</summary>
/// <remarks>
/// <para><strong>handle.exe emits a different row layout depending on how it was invoked</strong>, and
/// in one of the two the header does not describe its own rows. Both measured against Handle 5.0:</para>
/// <code>
/// name search   handle -u -v Fonts
///   header: Process,PID,User,Handle,Type,Share Flags,Name,Access      (8 columns)
///   row   : explorer.exe,3628,File,CONTOSO\user,0x68C,C:\...\StaticCache.dat   (6 fields)
///   actual: Process, PID, TYPE, USER, HANDLE, Name        <-- header order is wrong
///
/// process scope handle -a -p 14032 -u -v
///   header: Process,PID,User,Handle,Type,Share Flags,Name             (7 columns)
///   row   : explorer.exe,14032,CONTOSO\user,0x0C,Key,,HKLM\SOFTWARE\...          (7 fields)
///   actual: Process, PID, User, Handle, Type, Share Flags, Name       <-- header order is right
/// </code>
/// <para>So neither "always read by position" nor "always map by name" is correct. The layout is
/// identified from the header and the field positions chosen to match, and an unrecognised header is
/// refused outright.</para>
/// <para>That refusal is not theoretical caution: it is how the process-scoped layout was discovered.
/// The name-search indices were applied to a <c>-p</c> capture whose 7-field rows comfortably passed
/// a "long enough" check, and every field would have been attributed one column out -- user name
/// reported as the object type, handle value as the user -- with nothing in the result to show it.</para>
/// </remarks>
internal static class HandleCsvParser
{
    /// <summary>Where each value actually sits in a row, for one of handle.exe's layouts.</summary>
    private sealed record Layout(
        string Name,
        int Process,
        int Pid,
        int Type,
        int User,
        int Handle,
        int ObjectName,
        int MinimumFields);

    /// <summary>
    /// <c>handle -u -v &lt;name&gt;</c>: 8-column header ending in Access, above 6-field rows whose
    /// order the header misstates.
    /// </summary>
    private static readonly Layout NameSearch =
        new("name search", Process: 0, Pid: 1, Type: 2, User: 3, Handle: 4, ObjectName: 5, MinimumFields: 6);

    /// <summary>
    /// <c>handle -p &lt;pid&gt; -u -v</c>: 7-column header with no Access, above 7-field rows that do
    /// follow it.
    /// </summary>
    private static readonly Layout ProcessScoped =
        new("process scope", Process: 0, Pid: 1, Type: 4, User: 2, Handle: 3, ObjectName: 6, MinimumFields: 7);

    public static IReadOnlyList<HandleEntry> Parse(string csv)
    {
        if (string.IsNullOrWhiteSpace(csv))
        {
            return [];
        }

        var entries = new List<HandleEntry>();
        Layout? layout = null;

        using var reader = new StringReader(csv);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var fields = DelimitedLine.Split(line);

            if (layout is null && IsHeader(fields))
            {
                layout = IdentifyLayout(fields);
                continue;
            }

            if (layout is null || fields.Count < layout.MinimumFields)
            {
                // Unelevated runs interleave diagnostics such as
                // "Error obtaining handle information: Access denied" with the data. Those are not
                // rows; skipping keeps the partial result usable instead of failing the whole call.
                continue;
            }

            if (!int.TryParse(
                    fields[layout.Pid].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid))
            {
                continue;
            }

            entries.Add(new HandleEntry(
                ProcessName: fields[layout.Process].Trim(),
                ProcessId: pid,
                Type: fields[layout.Type].Trim(),
                User: NullIfEmpty(fields[layout.User]),
                HandleValue: fields[layout.Handle].Trim(),

                // Paths carry a trailing space in the captured output, and a path may itself contain
                // commas that handle.exe does not quote, so everything from the name column onwards
                // belongs to the name. The name is last in both layouts, so this is safe in both.
                Name: string.Join(',', fields.Skip(layout.ObjectName)).TrimEnd()));
        }

        return entries;
    }

    private static bool IsHeader(IReadOnlyList<string> fields) =>
        fields.Count > 1 && string.Equals(fields[0].Trim(), "Process", StringComparison.OrdinalIgnoreCase)
                         && string.Equals(fields[1].Trim(), "PID", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Picks the field positions for the layout in hand, or refuses if it is neither known one.
    /// </summary>
    /// <remarks>
    /// The presence of the trailing <c>Access</c> column is the discriminator, and it is a reliable
    /// one: it is what handle.exe adds in name-search mode, and it is exactly the mode whose rows do
    /// not follow the header. Refusing an unknown third layout is what keeps a future Sysinternals
    /// change from producing mis-attributed fields rather than an error.
    /// </remarks>
    private static Layout IdentifyLayout(IReadOnlyList<string> header)
    {
        var trimmed = header.Select(h => h.Trim()).ToArray();

        if (trimmed.Length == 8 && string.Equals(trimmed[7], "Access", StringComparison.OrdinalIgnoreCase))
        {
            return NameSearch;
        }

        if (trimmed.Length == 7 && string.Equals(trimmed[6], "Name", StringComparison.OrdinalIgnoreCase))
        {
            return ProcessScoped;
        }

        throw new FormatException(
            "handle.exe produced a CSV layout this parser was not written for (header: " +
            Truncate(string.Join(',', trimmed), 200) +
            "). Two layouts are known: an 8-column name-search header ending in 'Access', and a " +
            "7-column process-scoped header ending in 'Name'. Row field order differs between them, " +
            "so parsing an unrecognised one would mis-attribute every field.");
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max] + "...";

    private static string? NullIfEmpty(string value)
    {
        var trimmed = value.Trim();
        return trimmed.Length == 0 ? null : trimmed;
    }
}
