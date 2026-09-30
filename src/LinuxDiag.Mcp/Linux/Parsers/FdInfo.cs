namespace LinuxDiag.Mcp.Linux.Parsers;

/// <param name="Flags">The open flags, octal in the file.</param>
/// <param name="Locks">Each <c>lock:</c> line after its prefix: locks taken through this very open file.</param>
public sealed record FdInfoEntry(int? Flags, IReadOnlyList<string> Locks)
{
    /// <summary>O_ACCMODE: what the holder can do through this descriptor.</summary>
    public string? Access => Flags is not { } flags ? null : (flags & 3) switch
    {
        0 => "read",
        1 => "write",
        2 => "read-write",
        _ => null,
    };
}

/// <summary><c>/proc/&lt;pid&gt;/fdinfo/&lt;fd&gt;</c>.</summary>
public static class FdInfo
{
    public static FdInfoEntry Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        int? flags = null;
        var locks = new List<string>();
        foreach (var line in text.Split('\n'))
        {
            if (line.StartsWith("flags:", StringComparison.Ordinal))
            {
                flags = Convert.ToInt32(line[6..].Trim(), 8);
            }
            else if (line.StartsWith("lock:", StringComparison.Ordinal))
            {
                locks.Add(line[5..].Trim());
            }
        }

        return new FdInfoEntry(flags, locks);
    }
}
