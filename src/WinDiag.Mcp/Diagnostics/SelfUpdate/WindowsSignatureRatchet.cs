using System.Runtime.Versioning;
using Diag.Mcp.Server.SelfUpdate;
using Microsoft.Extensions.Logging;
using WinDiag.Mcp.Diagnostics.Signatures;

namespace WinDiag.Mcp.Diagnostics.SelfUpdate;

/// <summary>
/// A signed server accepts only a validly signed replacement from its own publisher.
/// </summary>
/// <remarks>
/// <para>Deliberately a ratchet rather than a setting. Unsigned development builds keep working, but once
/// a target runs a signed build it cannot be moved off its publisher through this path — which is
/// exactly the move an attacker with the token would want.</para>
/// <para>"Validly signed" alone was not a constraint: any publisher's signed binary passed, including a
/// verbatim copy of a catalog-signed Windows executable, which the service would then run as SYSTEM. So
/// the publisher is pinned to the running build's, compared by the full subject of the certificate
/// WinVerifyTrust verified -- not its thumbprint, which changes at every certificate renewal and would
/// strand a target on the build before it.</para>
/// <para>And it engages whenever the running build is signed at all, not only when its signature still
/// verifies. It used to switch itself off for anything but Valid, so a signature that had expired
/// without a timestamp, or that had stopped matching its file, disabled the check entirely. A running
/// build whose signer cannot be read is refused outright: there is no publisher to hold a replacement
/// to, and only someone at the console should decide that.</para>
/// <para>Publishers are read with <see cref="VerifiedSigner"/>, the rule the Sysinternals check beside the
/// server uses as well, so the two can never again disagree about who signed a file.</para>
/// <para>What it guards is the binary update_self installs, and nothing else beside it. The self-update
/// grant also lets put_file write the server's folder, and the .NET runtime loads some of its own imports
/// from there: a DLL planted that way loads at the next start, whatever this ratchet accepted -- a
/// re-staged copy of the current signed build included. That grant is code execution as the service's
/// account on its own, which is how SECURITY.md lists it; this ratchet narrows only what update_self
/// itself will run.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsSignatureRatchet : IUpdateGuard
{
    private readonly ISignatureInspector _signatures;
    private readonly ILogger<WindowsSignatureRatchet> _logger;

    public WindowsSignatureRatchet(ISignatureInspector signatures, ILogger<WindowsSignatureRatchet> logger)
    {
        _signatures = signatures;
        _logger = logger;
    }

    public void RequireAcceptable(string livePath, StagedBuild staged, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(staged);

        var current = _signatures.Inspect([livePath], cancellationToken).Files.Single();

        if (current.Verdict == SignatureVerdict.Unsigned)
        {
            _logger.LogWarning(
                "the running build is unsigned, so the replacement's signature ({Verdict}) is not enforced",
                staged.SignatureVerdict);
            return;
        }

        if (VerifiedSigner.Publisher(current) is not { } publisher)
        {
            throw new SelfUpdateRejectedException(
                $"This server's own executable carries a signature ({current.Verdict}: {current.Detail}) " +
                "whose signer could not be read, so there is no publisher to hold a replacement to and " +
                "update_self refuses rather than accept any. Nothing has been changed. Replace the build " +
                "at the console.");
        }

        if (current.Verdict != SignatureVerdict.Valid)
        {
            _logger.LogWarning(
                "the running build's signature no longer verifies ({Verdict}); still holding the replacement to its signer",
                current.Verdict);
        }

        // Compared by name because the engine carries the verdict as the text the caller is shown;
        // WindowsStagedBuildInspector writes it with ToString() on this same enum.
        if (staged.SignatureVerdict != nameof(SignatureVerdict.Valid))
        {
            throw new SelfUpdateRejectedException(
                $"This server is running a signed build, so it will only accept a validly signed replacement " +
                $"from the same publisher. The staged file is {staged.SignatureVerdict}: {staged.SignatureDetail} " +
                "Nothing has been changed.");
        }

        // Ordinal: both sides are X509Certificate2.Subject strings, produced the same way.
        if (!string.Equals(staged.SignerIdentity, publisher, StringComparison.Ordinal))
        {
            throw new SelfUpdateRejectedException(
                $"This server's build is signed by '{publisher}', and it accepts a replacement only from " +
                $"the same publisher. The staged file is validly signed, but by " +
                (staged.SignerIdentity is { } other ? $"'{other}'" : "a signer that could not be read") +
                ". Nothing has been changed.");
        }
    }
}
