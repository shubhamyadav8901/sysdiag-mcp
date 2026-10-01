using System.Text.RegularExpressions;

namespace MacDiag.Mcp.Mac.Parsers;

/// <summary>ls -le: each ACL entry on its own line under the file's, as " N: principal allow|deny rights [inherited]".</summary>
public static partial class LsAcl
{
    public static IReadOnlyList<string> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        return text.Split('\n')
            .Select(line => Entry().Match(line.TrimEnd('\r')))
            .Where(match => match.Success)
            .Select(match => match.Groups[1].Value.Trim())
            .ToList();
    }

    // The principal is everything before the first " allow " or " deny ": a directory group's name can hold spaces.
    [GeneratedRegex(@"^\s*\d+: ((?:user|group):.+? (?:allow|deny) .+)$")]
    private static partial Regex Entry();
}
