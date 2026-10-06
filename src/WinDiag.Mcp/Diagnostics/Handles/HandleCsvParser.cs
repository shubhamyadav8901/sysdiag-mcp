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
/// <para><strong>Within a layout, fields are found by shape, not by position.</strong> handle.exe
/// quotes nothing, and a comma is legal in an image name as well as in an object name. Read by fixed
/// position, <c>a,b.exe</c> put "b.exe" in the PID column and the row was skipped, so an elevated
/// search answered "nothing matched"; an image named <c>x,668,File,SYSTEM,0x4,svc.exe</c> pinned the
/// holder on PID 668. Rows are now anchored on the run of fields a real row must have -- a decimal PID
/// (the one asked for, under <c>-p</c>), an object type, and a <c>0x</c> handle value -- and a row that
/// fits no reading, or more than one, is counted rather than dropped or guessed at.</para>
/// <para><strong>Nor can a line be proven to start a row once a name that can hold a line break has
/// been printed.</strong> A row ends with a line break, and the name of an event, a mutant, a section, a
/// pipe or a registry key can contain one: the native APIs take any character but a backslash in a leaf
/// name, and an unprivileged user names their own objects. The text after the break read as a row of its
/// own, and <c>victim.exe,668,File,...,C:\shared\x.docx</c> inside an event's name pinned a file on PID
/// 668. Whatever handle.exe writes for a record end, a name can hold the same characters -- splitting on
/// "\r\n" only, or on a trailing space, is defeated by putting those in the name -- so the parser does
/// not try to find where the name stops. From the first such name on, a line is listed only if it claims
/// the process holding that object, and is marked <see cref="HandleEntry.Unproven"/>; any other line is
/// counted as unattributable. That is what can be proven: the process. Under <c>-p</c> every row is that
/// process, so the rows stay listed, marked. A name that cannot hold a break -- none, or a path on a drive
/// letter whose volume is NTFS, ReFS or FAT, which refuse control characters in a name -- leaves the next
/// line a row, which keeps the common search, file handles on local disks, fully proven.</para>
/// <para><strong>An image name can hold a line break too</strong>, and it is printed first: a process run
/// from a file on a mounted ISO is named whatever the image says. The text ahead of the break is a line of
/// its own -- a whole forged row, on a drive path no object-name rule doubts -- and nothing before it
/// gives it away. What does is the real row's line, which starts with only the text after the last break
/// under the real PID. So each row's printed image name is checked against the process table, read on both
/// sides of the run (<see cref="PrintedImageWitness"/>), and every line up to the last one it does not
/// confirm is counted as unattributable, or under <c>-p</c> listed and marked. A process that started or
/// exited during the run cannot be confirmed either, so its rows cost the lines before them the same way:
/// unattributable, never misattributed.</para>
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

    /// <param name="imagePrintedWhole">
    /// Whether an image name printed for a PID is the whole image name of one process that ran throughout
    /// the run (<see cref="PrintedImageWitness.IsWhole"/>). Required, so no caller can skip the check.
    /// </param>
    /// <param name="processId">
    /// The PID handle.exe was scoped to with <c>-p</c>, when it was. It anchors each row, so a PID spelled
    /// out inside an image name can never be taken for it.
    /// </param>
    /// <param name="driveRefusesControlCharacters">
    /// Whether the volume behind a drive letter refuses control characters in a name; null asks this
    /// machine (<see cref="RefusesControlCharacters(char)"/>). Supplied by tests, so the rule can be pinned
    /// on a machine with no drive letters.
    /// </param>
    public static HandleParseResult Parse(
        string csv,
        Func<int, string, bool> imagePrintedWhole,
        int? processId = null,
        Func<char, bool>? driveRefusesControlCharacters = null)
    {
        var refuses = Memoised(driveRefusesControlCharacters ?? RefusesControlCharacters);

        if (string.IsNullOrWhiteSpace(csv))
        {
            return new HandleParseResult([], 0);
        }

        Layout? layout = null;
        var expectedPid = processId?.ToString(CultureInfo.InvariantCulture);

        // Every line long enough to be a row, in order: read in full first, because a line can only be
        // judged once the last line whose image name could not be confirmed is known.
        var lines = new List<Line>();

        using var reader = new StringReader(csv);
        string? text;
        while ((text = reader.ReadLine()) is not null)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                continue;
            }

            var fields = DelimitedLine.Split(text);

            if (layout is null && IsHeader(fields))
            {
                layout = IdentifyLayout(fields);
                continue;
            }

            if (layout is null || fields.Count < layout.MinimumFields)
            {
                // Unelevated runs interleave diagnostics such as
                // "Error obtaining handle information: Access denied" with the data. Those are not rows;
                // skipping keeps the partial result usable instead of failing the whole call. A fragment
                // of a name is skipped the same way, and needs nothing more: one from an object name
                // follows a name that can hold a break, which already doubts what comes after, and one
                // from an image name precedes that row's own line, which no process confirms (below).
                continue;
            }

            var (anchored, fits) = Anchor(fields, layout, expectedPid);
            if (anchored is not { } pidIndex)
            {
                // Long enough to be a row, so a row that cannot be read is a holder this result would
                // otherwise silently omit -- counted, so the caller is never told "nothing matched" over it.
                // A line with two readings may be a real row whose image name ran on, so it confirms
                // nothing before it either. One with none cannot be: a real row always fits at its own
                // PID, so whatever that line is, the row it belongs to has a line of its own to judge.
                lines.Add(new Line(null, Unconfirmed: fits > 1, Breakable: true));
                continue;
            }

            int Column(int offset) => pidIndex + offset - layout.Pid;

            var entry = new HandleEntry(
                ProcessName: string.Join(',', fields.Take(pidIndex)).Trim(),
                ProcessId: int.Parse(fields[pidIndex].Trim(), NumberStyles.None, CultureInfo.InvariantCulture),
                Type: fields[Column(layout.Type)].Trim(),
                User: NullIfEmpty(fields[Column(layout.User)]),
                HandleValue: fields[Column(layout.Handle)].Trim(),

                // Paths carry a trailing space in the captured output, and a path may itself contain
                // commas that handle.exe does not quote, so everything from the name column onwards
                // belongs to the name. The name is last in both layouts, so this is safe in both.
                Name: string.Join(',', fields.Skip(Column(layout.ObjectName))).TrimEnd());

            lines.Add(new Line(
                entry,
                Unconfirmed: !imagePrintedWhole(entry.ProcessId, entry.ProcessName),
                Breakable: CanHoldLineBreak(entry.Name, refuses)));
        }

        // Every line up to this one may be text from inside an image name: see the remarks.
        var lastUnconfirmed = lines.FindLastIndex(l => l.Unconfirmed);

        var entries = new List<HandleEntry>();
        var unparsed = 0;

        // The process every later line must claim, once a name that can hold a line break has been
        // printed; null until then. Its image name too when that row is proven, since a line from inside
        // the name could otherwise list a made-up image under the right PID. NoProcess when the row is
        // not proven and nothing scoped it: a holder that may itself be forged vouches for nothing.
        (int Pid, string? Image)? doubtFrom = null;

        for (var i = 0; i < lines.Count; i++)
        {
            var (entry, _, breakable) = lines[i];
            var beforeUnconfirmed = i <= lastUnconfirmed;

            if (entry is not null &&
                (beforeUnconfirmed ? processId is not null : doubtFrom is not { } holder ||
                    (entry.ProcessId == holder.Pid &&
                     (holder.Image is null || string.Equals(entry.ProcessName, holder.Image, StringComparison.Ordinal)))))
            {
                // Under -p every row is the scoped process's, so one that may be forged is still that
                // process's: listed, and marked.
                entries.Add(entry with { Unproven = beforeUnconfirmed || doubtFrom is not null });
            }
            else
            {
                // Maybe a row, maybe text from inside a name naming a victim: nothing in the line can say
                // which, so it is counted and never listed against the PID it claims.
                unparsed++;
            }

            if (doubtFrom is null && breakable)
            {
                doubtFrom = entry is null || beforeUnconfirmed
                    ? (processId ?? NoProcess, null)
                    : (entry.ProcessId, entry.ProcessName);
            }
        }

        return new HandleParseResult(entries, unparsed, UnconfirmedImage: lastUnconfirmed >= 0);
    }

    /// <summary>One line long enough to be a row.</summary>
    /// <param name="Entry">What it reads as; null when it fits no single reading.</param>
    /// <param name="Unconfirmed">
    /// The process table does not confirm the image name it starts with, or it could not be read at all.
    /// </param>
    /// <param name="Breakable">Its object name could hold a line break, or could not be told apart.</param>
    private readonly record struct Line(HandleEntry? Entry, bool Unconfirmed, bool Breakable);

    /// <summary>
    /// Finds the PID column of a row whose image name may have pushed it right, or null when the row
    /// fits no reading or more than one; either way, how many readings it fits.
    /// </summary>
    /// <remarks>
    /// Every position is tried and every fit kept, because the first fit is the attacker's: a name built
    /// as <c>x,668,File,SYSTEM,0x4,svc.exe</c> fits at its own fake PID before the real one. Nothing in the
    /// row can settle two fits -- the forged reading's name column always contains the real one, so not
    /// even the search term separates them -- and an unreadable row is a better answer than a wrong PID.
    /// </remarks>
    private static (int? PidIndex, int Fits) Anchor(List<string> fields, Layout layout, string? expectedPid)
    {
        int? found = null;
        var fitCount = 0;

        // The name is last and may be empty, but its column must exist.
        var lastStart = fields.Count - (layout.MinimumFields - layout.Pid);

        for (var pid = layout.Pid; pid <= lastStart; pid++)
        {
            var offset = pid - layout.Pid;

            var fits = (expectedPid is null
                           ? IsPid(fields[pid])
                           : string.Equals(fields[pid].Trim(), expectedPid, StringComparison.Ordinal))
                       && IsObjectType(fields[layout.Type + offset])
                       && IsHandleValue(fields[layout.Handle + offset]);

            if (!fits)
            {
                continue;
            }

            fitCount++;
            found = pid;
        }

        return (fitCount == 1 ? found : null, fitCount);
    }

    /// <summary>A PID no row can carry, for doubt that began at a row whose process could not be read.</summary>
    private const int NoProcess = -1;

    /// <summary>Whether a printed object name could contain a line break, and so run on into the next line.</summary>
    /// <remarks>
    /// Only two kinds of name are taken not to: none, and a path on a drive letter whose volume refuses
    /// control characters in a name. The letter alone is not enough: a standard user can mount an ISO,
    /// and a UDF or CDFS name is whatever the image says. A file on a share is taken to print as
    /// <c>\Device\Mup\...</c>, as the object manager names it, which falls on the breakable side; no
    /// capture here shows a share, so that is an assumption this rests on. An object-manager name starts
    /// with a backslash and a registry key with its hive, so neither can be mistaken for a drive path.
    /// Everything else -- named objects, keys, pipes, devices -- is assumed to hold a break.
    /// </remarks>
    private static bool CanHoldLineBreak(string name, Func<char, bool> driveRefusesControlCharacters) =>
        name.Length > 0 &&
        !(name.Length >= 3 && char.IsAsciiLetter(name[0]) && name[1] == ':' && name[2] == '\\' &&
          driveRefusesControlCharacters(char.ToUpperInvariant(name[0])));

    /// <summary>The file systems whose drivers refuse a control character in a name.</summary>
    private static readonly HashSet<string> ControlCharacterFreeFormats =
        new(["NTFS", "ReFS", "FAT", "FAT32", "exFAT"], StringComparer.OrdinalIgnoreCase);

    /// <summary>Whether this machine's volume at <paramref name="letter"/> is one of those; anything unreadable is not.</summary>
    internal static bool RefusesControlCharacters(char letter)
    {
        try
        {
            return ControlCharacterFreeFormats.Contains(new DriveInfo(letter.ToString()).DriveFormat);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }

    /// <summary>One lookup per letter per parse: a result can name the same volume thousands of times.</summary>
    private static Func<char, bool> Memoised(Func<char, bool> lookup)
    {
        var known = new Dictionary<char, bool>();
        return letter => known.TryGetValue(letter, out var answer) ? answer : known[letter] = lookup(letter);
    }

    private static bool IsPid(string field)
    {
        var value = field.Trim();
        return value.Length is > 0 and <= 10 && value.All(char.IsAsciiDigit)
               && int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out _);
    }

    /// <summary>File, Key, Section, ALPC Port, WindowStation...: letters, digits and the odd space.</summary>
    private static bool IsObjectType(string field)
    {
        var value = field.Trim();
        return value.Length > 0 && char.IsAsciiLetter(value[0])
               && value.All(c => char.IsAsciiLetterOrDigit(c) || c == ' ');
    }

    /// <summary>handle.exe prints handle values as <c>0x</c> and hex digits: <c>0x0000068C</c>.</summary>
    private static bool IsHandleValue(string field)
    {
        var value = field.Trim();
        return value.Length > 2 && value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
               && !value.AsSpan(2).ContainsAnyExcept("0123456789abcdefABCDEF");
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

/// <summary>What one run of handle.exe parsed to.</summary>
/// <param name="UnparsedRows">
/// Rows long enough to be data that could not be attributed to one process: an ambiguous image name, a
/// line after an object name that can hold a line break that claims another process, or a line at or
/// before the last one whose image name the process table did not confirm. Each may be a handle that
/// exists and is not in <see cref="Entries"/>.
/// </param>
/// <param name="UnconfirmedImage">Some line's image name was not confirmed by the process table.</param>
internal sealed record HandleParseResult(IReadOnlyList<HandleEntry> Entries, int UnparsedRows, bool UnconfirmedImage = false);
