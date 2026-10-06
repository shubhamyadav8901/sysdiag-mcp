using Diag.Mcp.Core;
using Diag.Mcp.Server.Files;

namespace WinDiag.Mcp.Tools;

/// <summary>Refuses a network or device path for every tool that opens a path it was given.</summary>
/// <remarks>
/// <para><c>\\host\share\x</c> handed to <c>who_locks_path</c>, <c>file_signatures</c>,
/// <c>effective_access</c> or <c>query_activity</c> made this server open an SMB connection to that host
/// and, as LocalSystem, authenticate with the machine account -- coerced authentication, ready to relay to
/// LDAP or AD CS. All four are registered on a read-only server, so a token with no grants could do it.</para>
/// <para>The spelling rule is the kit's <see cref="NetworkPath"/>, the one get_file and put_file also go
/// through. Arbitrary read lifts it: that grant already means "anything this account can open", shares
/// included. Checked before anything touches the path, since a mere existence check is the connection.</para>
/// </remarks>
internal static class LocalPathGuard
{
    /// <exception cref="ArgumentException">The path reaches the network or a device, and arbitrary read is off.</exception>
    /// <remarks>
    /// A path that cannot be canonicalised is left to the tool, which already reports it in its own words;
    /// it cannot reach anything, so there is nothing to refuse here.
    /// </remarks>
    public static void RequireLocal(string path, string parameterName, FileTransferOptions files)
    {
        if (files.AllowArbitraryRead)
        {
            return;
        }

        string full;
        try
        {
            full = Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return;
        }

        if (NetworkPath.IsNetworkOrDevice(full))
        {
            throw new ArgumentException(
                $"'{path}' is a network share or a device, not a file on this machine's local disks. Opening " +
                "it would make this server connect to that host and sign in as its own account -- the " +
                "machine account when it runs as SYSTEM -- so it is refused, and nothing was opened. Pass a " +
                $"path on a local drive, or set {files.ArbitraryReadSetting} on the server to allow it.",
                parameterName);
        }
    }
}
