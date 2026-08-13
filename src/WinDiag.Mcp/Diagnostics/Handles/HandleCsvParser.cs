using System.Globalization;
using System.Text;

namespace WinDiag.Mcp.Diagnostics.Handles;

/// <summary>Parses the CSV that <c>handle.exe -u -v</c> writes.</summary>
/// <remarks>
/// <para><strong>handle.exe's CSV header does not describe its own data rows.</strong> Verified against
/// Sysinternals Suite 2026.6.0.0 on Windows 11 (fixture
/// <c>tests/WinDiag.Mcp.Tests/Fixtures/handle-u-v-fonts.csv</c>), <c>-u -v</c> emits:</para>
/// <code>
/// header: Process,PID,User,Handle,Type,Share Flags,Name,Access      (8 columns)
/// row   : explorer.exe,3628,File,CONTOSO\user,0x0000068C,C:\Windows\Fonts\StaticCache.dat  (6 fields)
/// </code>
/// <para>The real row layout is <c>Process, PID, Type, User, Handle, Name</c>. Share flags and granted
/// access are advertised by the header but never emitted.</para>
/// <para>Consequently this parser reads <em>by position</em>. Mapping by header name -- the obvious
/// defensive choice -- would read Type as User, User as Handle, Handle as Type and Name as Share
/// Flags, silently attributing every field to the wrong column. The header is used only to recognise
/// that the output is handle.exe CSV at all.</para>
/// </remarks>
internal static class HandleCsvParser
{
    private const int ProcessIndex = 0;
    private const int PidIndex = 1;
    private const int TypeIndex = 2;
    private const int UserIndex = 3;
    private const int HandleIndex = 4;
    private const int NameIndex = 5;

    /// <summary>Minimum fields in a usable row, given the pinned <c>-u -v</c> flag set.</summary>
    private const int RequiredFieldCount = 6;

    public static IReadOnlyList<HandleEntry> Parse(string csv)
    {
        if (string.IsNullOrWhiteSpace(csv))
        {
            return [];
        }

        var entries = new List<HandleEntry>();
        var sawHeader = false;

        using var reader = new StringReader(csv);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var fields = SplitCsvLine(line);

            if (!sawHeader && IsHeader(fields))
            {
                RequireSupportedLayout(fields);
                sawHeader = true;
                continue;
            }

            if (fields.Count < RequiredFieldCount)
            {
                // Unelevated runs interleave diagnostics such as
                // "Error obtaining handle information: Access denied" with the data. Those are not
                // rows; skipping keeps the partial result usable instead of failing the whole call.
                continue;
            }

            if (!int.TryParse(fields[PidIndex].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid))
            {
                continue;
            }

            entries.Add(new HandleEntry(
                ProcessName: fields[ProcessIndex].Trim(),
                ProcessId: pid,
                Type: fields[TypeIndex].Trim(),
                User: NullIfEmpty(fields[UserIndex]),
                HandleValue: fields[HandleIndex].Trim(),

                // Paths carry a trailing space in the captured output, and a path may itself contain
                // commas, so anything past the name index belongs to the name.
                Name: string.Join(',', fields.Skip(NameIndex)).TrimEnd()));
        }

        return entries;
    }

    private static bool IsHeader(IReadOnlyList<string> fields) =>
        fields.Count > 1 && string.Equals(fields[0].Trim(), "Process", StringComparison.OrdinalIgnoreCase)
                         && string.Equals(fields[1].Trim(), "PID", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Refuses to parse any layout other than the name-search one this parser was written against.
    /// </summary>
    /// <remarks>
    /// handle.exe's row layout depends on how it was invoked, not only on its flags. The name search
    /// used here emits an 8-column header ending in <c>Access</c> above 6-field rows. Process-scoped
    /// invocation (<c>-p</c>) instead emits a 7-column header with no <c>Access</c> above 7-field rows
    /// that <em>do</em> follow header order -- and those rows have enough fields to satisfy
    /// <see cref="RequiredFieldCount"/>, so positional parsing would accept them and silently place
    /// the user name in <c>Type</c>, the handle in <c>User</c>, and so on.
    /// <para>Failing loudly here is what stops a future "just add -p scoping" change from quietly
    /// producing wrong attributions instead of an error.</para>
    /// </remarks>
    private static void RequireSupportedLayout(IReadOnlyList<string> header)
    {
        var isNameSearchLayout = header.Count == 8
                                 && string.Equals(header[7].Trim(), "Access", StringComparison.OrdinalIgnoreCase);

        if (!isNameSearchLayout)
        {
            throw new FormatException(
                "handle.exe produced a CSV layout this parser was not written for (header: " +
                Truncate(string.Join(',', header.Select(h => h.Trim())), 200) +
                "). The expected name-search layout is an 8-column header ending in 'Access'. " +
                "Row field order is layout-dependent, so parsing this would mis-attribute every field.");
        }
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max] + "...";

    /// <summary>Splits one CSV line, honouring double-quoted fields and doubled quote escapes.</summary>
    /// <remarks>
    /// Hand-rolled rather than taking a CSV dependency: the grammar needed is one line and one
    /// delimiter, and the only awkward case -- a comma inside a path -- is handled here and again by
    /// the name-rejoining above, since handle.exe does not quote such paths.
    /// </remarks>
    internal static List<string> SplitCsvLine(string line)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;

        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];

            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"')
                    {
                        current.Append('"');
                        i++;
                    }
                    else
                    {
                        inQuotes = false;
                    }
                }
                else
                {
                    current.Append(c);
                }
            }
            else if (c == '"')
            {
                inQuotes = true;
            }
            else if (c == ',')
            {
                fields.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }

        fields.Add(current.ToString());
        return fields;
    }

    private static string? NullIfEmpty(string value)
    {
        var trimmed = value.Trim();
        return trimmed.Length == 0 ? null : trimmed;
    }
}
