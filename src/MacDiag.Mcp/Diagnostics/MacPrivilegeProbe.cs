namespace MacDiag.Mcp.Diagnostics;

/// <summary>Root or not: what the privileged tools need on macOS.</summary>
public sealed class MacPrivilegeProbe : IPrivilegeProbe
{
    public bool IsElevated => Environment.IsPrivilegedProcess;

    public string PrivilegeName => "root";

    public string HowToElevate => "Run the server as root; the macdiag launchd daemon does.";
}
