namespace LinuxDiag.Mcp.Linux.External;

/// <summary>The kit's runner with Linux's system directories, a UTF-8 C locale and systemd's pager settings.</summary>
public sealed class LinuxExternalCommand : SystemCommand
{
    /// <summary>Where programs are taken from, and the child's whole PATH.</summary>
    internal static readonly string[] SystemDirectories = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"];

    public LinuxExternalCommand()
        : base(SystemDirectories)
    {
    }

    internal LinuxExternalCommand(int maxOutputChars)
        : base(SystemDirectories, maxOutputChars)
    {
    }

    protected override string Locale => "C.UTF-8";

    protected override void AddEnvironment(IDictionary<string, string?> environment)
    {
        environment["SYSTEMD_PAGER"] = "cat";
        environment["SYSTEMD_COLORS"] = "0";
    }
}
