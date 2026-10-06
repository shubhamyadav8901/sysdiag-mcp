using System.Runtime.Versioning;
using Diag.Mcp.Server.SelfUpdate;
using WinDiag.Mcp.Diagnostics.Signatures;

namespace WinDiag.Mcp.Diagnostics.SelfUpdate;

/// <summary>Hashes a staged build and reads its Authenticode signature through WinTrust.</summary>
/// <remarks>
/// Both from one held, deny-writers handle (<see cref="ISignatureInspector.InspectHeld"/>). Read from two
/// opens, a <c>put_file</c> landing between them paired a signed verdict with an unsigned file's hash --
/// and that hash is the one the restart helper checks before it installs the file.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsStagedBuildInspector : IStagedBuildInspector
{
    private readonly ISignatureInspector _signatures;

    public WindowsStagedBuildInspector(ISignatureInspector signatures)
    {
        _signatures = signatures;
    }

    public StagedBuild Inspect(string path, CancellationToken cancellationToken)
    {
        FileSignature file;
        try
        {
            file = _signatures.InspectHeld(path, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new SelfUpdateRejectedException(
                $"The staged build at '{path}' could not be read with writers locked out ({ex.Message}). " +
                "Something may still have it open for writing - a transfer still in progress, say. " +
                "Nothing has been changed; call again once it has finished.");
        }

        return new StagedBuild(
            path, file.Sha256, file.SizeBytes, file.Verdict.ToString(), file.Detail, file.SignerSubject);
    }
}
