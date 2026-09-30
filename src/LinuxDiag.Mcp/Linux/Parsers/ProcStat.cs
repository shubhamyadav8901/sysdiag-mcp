using System.Globalization;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <summary>The fields this server reads from one <c>/proc/&lt;pid&gt;/stat</c> line.</summary>
/// <param name="State">One letter: R, S, D, Z, T, t, I, X.</param>
/// <param name="StartTimeTicks">Start time in clock ticks after boot -- the identity check for PID reuse.</param>
public sealed record ProcStatEntry(
    int ProcessId, string Name, string State, int ParentProcessId, uint Flags, int ThreadCount,
    long StartTimeTicks, long ResidentPages)
{
    /// <summary>PF_KTHREAD. The only reliable mark of a kernel thread: in WSL, PID 2 is not kthreadd.</summary>
    public const uint KernelThreadFlag = 0x00200000;

    public bool IsKernelThread => (Flags & KernelThreadFlag) != 0;
}

public static class ProcStat
{
    /// <summary>Parses by proc(5)'s field numbers, counting from the last ')'.</summary>
    /// <remarks>
    /// The name sits in parentheses and may itself hold ')' and spaces -- WSL's PID 2 is
    /// "init-systemd(Ub". Splitting on spaces, or at the first ')', reads every later field one place off.
    /// </remarks>
    public static ProcStatEntry Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var open = text.IndexOf('(', StringComparison.Ordinal);
        var close = text.LastIndexOf(')');
        if (open <= 0 || close < open)
        {
            throw new FormatException($"/proc/<pid>/stat has no '(name)' field: '{Excerpt(text)}'.");
        }

        // fields[0] is proc(5)'s field 3, so field N is fields[N - 3].
        var fields = text[(close + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 22)
        {
            throw new FormatException(
                $"/proc/<pid>/stat has {fields.Length + 2} fields where proc(5) documents at least 24: '{Excerpt(text)}'.");
        }

        return new ProcStatEntry(
            Int(text.AsSpan(0, open).Trim()),
            text[(open + 1)..close],
            fields[0],
            Int(fields[1]),
            uint.Parse(fields[6], NumberStyles.None, CultureInfo.InvariantCulture),
            Int(fields[17]),
            long.Parse(fields[19], NumberStyles.None, CultureInfo.InvariantCulture),
            long.Parse(fields[21], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture));
    }

    private static int Int(ReadOnlySpan<char> value) =>
        int.Parse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);

    private static string Excerpt(string text) => text.Length <= 80 ? text.TrimEnd() : text[..80] + "...";
}
