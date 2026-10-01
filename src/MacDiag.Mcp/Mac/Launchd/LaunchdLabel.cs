using System.Text.RegularExpressions;

namespace MacDiag.Mcp.Mac.Launchd;

/// <summary>The one rule for a launchd label a caller supplies, used by every tool and by the installer.</summary>
/// <remarks>
/// Letters, digits, dot, dash and underscore only, and never starting with a dot or a dash: a label is spliced into
/// "system/&lt;label&gt;" and into plist paths that are written and deleted as root, so it may carry no separator, and
/// one starting with "-" would be read by launchctl as an option.
/// </remarks>
public static partial class LaunchdLabel
{
    public static string Check(string? label, string parameterName)
    {
        if (string.IsNullOrEmpty(label) || !Shape().IsMatch(label) || label[0] is '.' or '-')
        {
            throw new ArgumentException(
                $"'{label}' is not a launchd label: use letters, digits, '.', '-' and '_' only, for example com.example.daemon.",
                parameterName);
        }

        return label;
    }

    public static bool IsValid(string? label) =>
        !string.IsNullOrEmpty(label) && Shape().IsMatch(label) && label[0] is not ('.' or '-');

    // \z, not $: in .NET $ also matches before a final newline, which would let "com.x\n" through.
    [GeneratedRegex(@"^[A-Za-z0-9._-]+\z")]
    private static partial Regex Shape();
}
