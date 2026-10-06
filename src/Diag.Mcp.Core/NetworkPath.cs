namespace Diag.Mcp.Core;

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
    public static bool IsNetworkOrDevice(string fullPath) =>
        IsNetworkOrDevice(fullPath, OperatingSystem.IsWindows(), DriveTypeOf);

    /// <summary>The rule, with the OS and the drive-type lookup supplied, so it can be pinned on any machine.</summary>
    /// <remarks>
    /// <para>Two leading separators, in either direction, are a UNC path (<c>\\host\share</c>) or a
    /// device path (<c>\\?\</c>, <c>\\.\</c>), and <c>\??\</c> is the NT spelling of the latter. Of those,
    /// only a device prefix followed by a drive letter and a separator -- <c>\\?\C:\</c>, how a caller
    /// reaches past MAX_PATH -- is a local file. Everything else is refused: <c>\\?\UNC\</c>, a named
    /// pipe, <c>\\.\C:</c> (the raw volume), <c>\\?\GLOBALROOT</c> (the whole object namespace) and
    /// <c>\\?\Volume{guid}</c>, which is local storage but skips the drive-letter spelling the owned
    /// directories are configured in.</para>
    /// <para>A drive letter the system reports as a network drive is refused too, however it is spelled:
    /// a share mapped for every session is reached by the same SMB connection as its UNC spelling. The
    /// type is asked of the letter, not of the path's root. <see cref="DriveInfo"/> refuses a root such as
    /// <c>\\?\Z:\</c>, and taking that refusal for "local" let the long-path spelling of a mapped share
    /// through.</para>
    /// </remarks>
    public static bool IsNetworkOrDevice(string path, bool windows, Func<char, DriveType> driveTypeOf)
    {
        if (!windows || path.Length < 2)
        {
            return false;
        }

        static bool Separator(char c) => c is '\\' or '/';
        static bool Drive(ReadOnlySpan<char> s) => s.Length >= 2 && char.IsAsciiLetter(s[0]) && s[1] == ':';

        var devicePrefix = Separator(path[0]) && Separator(path[1]);
        var ntPrefix = path.StartsWith(@"\??\", StringComparison.Ordinal);
        if (!devicePrefix && !ntPrefix)
        {
            return Drive(path) && driveTypeOf(path[0]) == DriveType.Network;
        }

        var isDeviceForm = ntPrefix || (path.Length >= 4 && path[2] is '?' or '.' && Separator(path[3]));
        if (!isDeviceForm)
        {
            return true;
        }

        var rest = path.AsSpan(4);
        var localDrive = Drive(rest) && rest.Length >= 3 && Separator(rest[2]);
        return !localDrive || driveTypeOf(rest[0]) == DriveType.Network;
    }

    /// <summary>The type Windows reports for a drive letter, asked without touching the drive.</summary>
    /// <remarks>GetDriveType answers a mapped drive from the session's mapping, not by connecting to it.</remarks>
    public static DriveType DriveTypeOf(char letter)
    {
        try
        {
            return new DriveInfo(letter.ToString()).DriveType;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException)
        {
            return DriveType.Unknown;
        }
    }
}
