namespace MacDiag.Mcp.Mac;

/// <summary>The kit's runner with macOS's system directories only, and the C locale.</summary>
/// <remarks>
/// /usr/local and /opt/homebrew can belong to an admin user, so a root daemon never takes programs from them.
/// The locale is plain C: macOS promises no C.UTF-8, and tools/capture-macos-fixtures.sh captures under C too.
/// </remarks>
public sealed class MacSystemCommand : SystemCommand
{
    public static readonly string[] SystemDirectories = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

    public MacSystemCommand()
        : base(SystemDirectories)
    {
    }
}
