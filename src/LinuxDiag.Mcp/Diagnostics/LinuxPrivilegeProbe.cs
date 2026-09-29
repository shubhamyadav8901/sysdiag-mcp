namespace LinuxDiag.Mcp.Diagnostics;

/// <summary>Root or not: what the privileged tools need on Linux.</summary>
public sealed class LinuxPrivilegeProbe : IPrivilegeProbe
{
    public bool IsElevated => Environment.IsPrivilegedProcess;

    public string PrivilegeName => "root";

    public string HowToElevate => "Run the server as root; the linuxdiag service does.";
}
