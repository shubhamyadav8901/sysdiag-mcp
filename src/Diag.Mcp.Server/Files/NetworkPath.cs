namespace Diag.Mcp.Server.Files;

/// <summary>Whether opening a path would make the server connect out or open a device, rather than read a local file.</summary>
/// <remarks>
/// <para>On Windows, <c>\\host\share\x</c> is an SMB connection, and a server running as LocalSystem
/// authenticates it with the machine account: anyone holding the token -- read-only included, since every
/// read tool takes a path -- could aim that at a host of their choosing and relay it. Judging such a path
/// by walking it, as the scope check does, is already the connection, so it has to be recognised by
/// spelling, before any filesystem call.</para>
/// <para>One rule for every path-taking tool, here rather than in each, so the next tool that takes a
/// path cannot spell the check differently. On Linux and macOS a leading <c>//</c> is only a root and
/// nothing here applies.</para>
/// </remarks>
public static class NetworkPath
{
    /// <summary>Whether <paramref name="fullPath"/> reaches the network or a device on this machine.</summary>
    /// <remarks>
    /// Also true for a drive letter the system reports as a network drive: a share mapped for every
    /// session is reached by the same SMB connection as its UNC spelling. <see cref="DriveInfo"/> asks
    /// the drive's type without connecting.
    /// </remarks>
    public static bool IsNetworkOrDevice(string fullPath)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        if (IsNetworkOrDevice(fullPath, windows: true))
        {
            return true;
        }

        try
        {
            var root = Path.GetPathRoot(fullPath);
            return !string.IsNullOrEmpty(root) && new DriveInfo(root).DriveType == DriveType.Network;
        }
        catch (ArgumentException)
        {
            // Not a drive DriveInfo recognises: the spelling check above has already said it is local.
            return false;
        }
    }

    /// <summary>The spelling rule alone, with the OS supplied, so it can be pinned on any machine.</summary>
    /// <remarks>
    /// <para>Two leading separators, in either direction, are a UNC path (<c>\\host\share</c>) or a
    /// device path (<c>\\?\</c>, <c>\\.\</c>), and <c>\??\</c> is the NT spelling of the latter. Of those,
    /// only a device prefix followed by a drive letter and a separator -- <c>\\?\C:\</c>, how a caller
    /// reaches past MAX_PATH -- is a local file. Everything else is refused: <c>\\?\UNC\</c>, a named
    /// pipe, <c>\\.\C:</c> (the raw volume), <c>\\?\GLOBALROOT</c> (the whole object namespace) and
    /// <c>\\?\Volume{guid}</c>, which is local storage but skips the drive-letter spelling the owned
    /// directories are configured in.</para>
    /// </remarks>
    internal static bool IsNetworkOrDevice(string path, bool windows)
    {
        if (!windows || path.Length < 2)
        {
            return false;
        }

        static bool Separator(char c) => c is '\\' or '/';

        var devicePrefix = Separator(path[0]) && Separator(path[1]);
        var ntPrefix = path.StartsWith(@"\??\", StringComparison.Ordinal);
        if (!devicePrefix && !ntPrefix)
        {
            return false;
        }

        var isDeviceForm = ntPrefix || (path.Length >= 4 && path[2] is '?' or '.' && Separator(path[3]));
        if (!isDeviceForm)
        {
            return true;
        }

        var rest = path.AsSpan(4);
        var localDrive = rest.Length >= 3 && char.IsAsciiLetter(rest[0]) && rest[1] == ':' && Separator(rest[2]);
        return !localDrive;
    }
}
