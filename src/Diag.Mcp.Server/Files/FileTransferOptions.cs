namespace Diag.Mcp.Server.Files;

/// <summary>What the transfer tools may touch, and how to tell a caller to widen it.</summary>
/// <param name="ArtifactDirectory">
/// Owned by the server, beside its own directory. There is deliberately no default: on Linux the
/// obvious one, the temp directory, is the shared world-writable /tmp -- the defect already fixed once
/// in the relay. Each server must choose.
/// </param>
/// <param name="AllowArbitraryWrite">Whether <c>put_file</c> may write outside the owned directories.</param>
/// <param name="AllowArbitraryRead">Whether <c>get_file</c> may read outside the owned directories.</param>
/// <param name="ArbitraryWriteSetting">The setting a refusal names, e.g. "LINUXDIAG_ALLOW_ARBITRARY_WRITE=1".</param>
/// <param name="ArbitraryReadSetting">The setting a refusal names, e.g. "LINUXDIAG_ALLOW_ARBITRARY_READ=1".</param>
/// <param name="ServerDirectoryWritable">
/// Whether <c>put_file</c> may write into the server's own directory without arbitrary write. It
/// defaults to true because that is how windiag has always staged a build for <c>update_self</c>; a
/// server whose binary is a root service's -- LinuxDiag -- ties it to its self-update grant instead.
/// </param>
/// <param name="ServerDirectorySetting">The setting a refusal names, e.g. "LINUXDIAG_ALLOW_SELF_UPDATE=1".</param>
/// <remarks>
/// There is no read-only flag here: a read-only server does not register <c>put_file</c> at all, so a
/// flag the receiver would never read has no place on it.
/// </remarks>
public sealed record FileTransferOptions(
    string ArtifactDirectory,
    bool AllowArbitraryWrite,
    bool AllowArbitraryRead,
    string ArbitraryWriteSetting,
    string ArbitraryReadSetting,
    bool ServerDirectoryWritable = true,
    string? ServerDirectorySetting = null)
{
    // Checked here rather than when the refusal is built: by then the caller is holding a message that
    // reads "Set  to allow it", which is the one sentence meant to unblock them.
    public string? ServerDirectorySetting { get; init; } =
        ServerDirectoryWritable || !string.IsNullOrWhiteSpace(ServerDirectorySetting)
            ? ServerDirectorySetting
            : throw new ArgumentException(
                "A server directory that is not writable needs the setting its refusal names.",
                nameof(ServerDirectorySetting));
}
