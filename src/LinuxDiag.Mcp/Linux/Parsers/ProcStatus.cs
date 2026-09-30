using System.Globalization;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <summary>The fields this server reads from <c>/proc/&lt;pid&gt;/status</c>.</summary>
/// <param name="RealUserId">A long: uids reach 2^32-2 under user namespaces.</param>
/// <param name="NamespaceProcessIds">NSpid: the PID in each PID namespace, outermost first.</param>
public sealed record ProcStatusEntry(long? RealUserId, IReadOnlyList<int> NamespaceProcessIds)
{
    /// <summary>The PID the innermost namespace sees -- inside a container, its own PID -- or null outside one.</summary>
    public int? InnermostProcessId => NamespaceProcessIds.Count > 1 ? NamespaceProcessIds[^1] : null;
}

public static class ProcStatus
{
    public static ProcStatusEntry Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        long? uid = null;
        var nspids = new List<int>();
        foreach (var line in text.Split('\n'))
        {
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon < 0)
            {
                continue;
            }

            var values = line[(colon + 1)..].Split(['\t', ' '], StringSplitOptions.RemoveEmptyEntries);
            switch (line[..colon])
            {
                case "Uid" when values.Length > 0:
                    uid = long.Parse(values[0], NumberStyles.None, CultureInfo.InvariantCulture);
                    break;
                case "NSpid":
                    nspids.AddRange(values.Select(v => int.Parse(v, NumberStyles.None, CultureInfo.InvariantCulture)));
                    break;
            }
        }

        return new ProcStatusEntry(uid, nspids);
    }
}
