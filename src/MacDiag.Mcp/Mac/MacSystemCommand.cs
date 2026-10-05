namespace MacDiag.Mcp.Mac;

/// <summary>The kit's runner with macOS's system directories only, and the C locale -- ps excepted.</summary>
/// <remarks>
/// /usr/local and /opt/homebrew can belong to an admin user, so a root daemon never takes programs from them.
/// The locale is plain C: older macOS promises no C.UTF-8, and tools/capture-macos-fixtures.sh captures under C too.
/// </remarks>
public sealed class MacSystemCommand : SystemCommand
{
    public static readonly string[] SystemDirectories = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

    public MacSystemCommand()
        : base(SystemDirectories)
    {
    }

    /// <remarks>
    /// <para>ps under C prints every byte above 0x7F as a vis sequence with no backslash -- "café" as "cafM-CM-)" -- and
    /// leaves a literal "M-C" or backslash as it is, so the output cannot be decoded back; measured on macOS 26. With a
    /// UTF-8 LC_CTYPE it prints valid UTF-8 byte for byte. Measured too: lstart, stat and the numeric columns are
    /// identical under it, since LC_TIME stays C.</para>
    /// <para>en_US.UTF-8, not C.UTF-8: every macOS release ships it, and only its character set is used here. Every ps
    /// call gets it, so the identity checks in process_control compare like with like.</para>
    /// </remarks>
    protected override string? CharacterLocaleFor(string program) =>
        string.Equals(program, "ps", StringComparison.Ordinal) ? "en_US.UTF-8" : null;
}
