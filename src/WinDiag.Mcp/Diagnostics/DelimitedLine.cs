using System.Text;

namespace WinDiag.Mcp.Diagnostics;

/// <summary>
/// Splits one line of delimited text, honouring quoted fields.
/// </summary>
/// <remarks>
/// Shared because three parsers here read delimited output from tools that quote inconsistently, and
/// each getting its own splitter is how they drift. The rules implemented are RFC 4180's: a field may
/// be wrapped in double quotes, a delimiter inside quotes is data, and a doubled quote inside a quoted
/// field is one literal quote.
/// <para>Quoting is not optional to support. <c>autorunsc -c</c> emits unquoted fields until a
/// description contains a comma, at which point it quotes that field and only that field -- so a naive
/// <c>Split(',')</c> reads correctly for most of a capture and then silently shifts every column on
/// the rows that matter most, which are the ones with prose in them.</para>
/// </remarks>
internal static class DelimitedLine
{
    public static List<string> Split(string line, char delimiter = ',')
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
            else if (c == delimiter)
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
}
