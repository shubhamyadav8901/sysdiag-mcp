using System.Text;

namespace WinDiag.Mcp.Diagnostics.External;

/// <summary>Shared CSV reading for external tool output.</summary>
/// <remarks>
/// Hand-rolled rather than taking a dependency: the grammar needed is one delimiter and quoted fields,
/// and the awkward cases — a comma inside a path, a quote inside a detail string — are handled here once
/// rather than in each parser.
/// </remarks>
internal static class DelimitedText
{
    /// <summary>Splits a single line, honouring double-quoted fields and doubled-quote escapes.</summary>
    public static List<string> SplitLine(string line)
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

    /// <summary>
    /// Streams records from a reader, one record at a time, never holding the whole file.
    /// </summary>
    /// <remarks>
    /// <para>A capture CSV runs to hundreds of megabytes — a measured 65 MB for twenty seconds of
    /// unfiltered tracing — so reading it into memory is not an option.</para>
    /// <para>This is a character-level state machine rather than a read-a-line-then-split loop because a
    /// quoted field may legitimately contain a newline. A line-based reader silently truncates such a
    /// record and shifts every field after it, which looks like data rather than an error.</para>
    /// </remarks>
    public static IEnumerable<List<string>> ReadRecords(TextReader reader, CancellationToken cancellationToken)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;
        var sawAny = false;
        var buffer = new char[8192];
        int read;

        while ((read = reader.Read(buffer, 0, buffer.Length)) > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            for (var i = 0; i < read; i++)
            {
                var c = buffer[i];

                if (inQuotes)
                {
                    if (c != '"')
                    {
                        current.Append(c);
                        continue;
                    }

                    // Peek for a doubled quote, refilling across a buffer boundary if needed.
                    var next = i + 1 < read ? buffer[i + 1] : (char)reader.Peek();
                    if (next == '"')
                    {
                        current.Append('"');
                        if (i + 1 < read) { i++; } else { reader.Read(); }
                    }
                    else
                    {
                        inQuotes = false;
                    }

                    continue;
                }

                switch (c)
                {
                    case '"':
                        inQuotes = true;
                        sawAny = true;
                        break;

                    case ',':
                        fields.Add(current.ToString());
                        current.Clear();
                        sawAny = true;
                        break;

                    case '\r':
                        break;

                    case '\n':
                        if (sawAny || current.Length > 0 || fields.Count > 0)
                        {
                            fields.Add(current.ToString());
                            yield return fields;
                            fields = [];
                            current.Clear();
                            sawAny = false;
                        }

                        break;

                    default:
                        current.Append(c);
                        sawAny = true;
                        break;
                }
            }
        }

        if (sawAny || current.Length > 0 || fields.Count > 0)
        {
            fields.Add(current.ToString());
            yield return fields;
        }
    }
}
