using System.Runtime.Versioning;
using Diag.Mcp.Server.SelfUpdate;
using Microsoft.Extensions.Logging;
using WinDiag.Mcp.Diagnostics.Signatures;

namespace WinDiag.Mcp.Diagnostics.SelfUpdate;

/// <summary>
/// A signed server refuses an unsigned or untrusted replacement.
/// </summary>
/// <remarks>
/// Deliberately a ratchet rather than a setting. Unsigned development builds keep working, but once
/// a target runs a signed build it cannot be downgraded to an unsigned one through this path — which
/// is exactly the move an attacker with the token would want.
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
        var current = _signatures.Inspect([livePath], cancellationToken).Files.Single();

        if (current.Verdict != SignatureVerdict.Valid)
        {
            _logger.LogWarning(
                "the running build is unsigned, so the replacement's signature ({Verdict}) is not enforced",
                staged.SignatureVerdict);
            return;
        }

        // Compared by name because the engine carries the verdict as the text the caller is shown;
        // WindowsStagedBuildInspector writes it with ToString() on this same enum.
        if (staged.SignatureVerdict != nameof(SignatureVerdict.Valid))
        {
            throw new SelfUpdateRejectedException(
                $"This server is running a signed build, so it will only accept a signed replacement. " +
                $"The staged file is {staged.SignatureVerdict}: {staged.SignatureDetail} Nothing has been changed.");
        }
    }
}
