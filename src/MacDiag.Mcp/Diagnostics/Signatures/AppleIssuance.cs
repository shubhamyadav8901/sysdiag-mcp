using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Signatures;

public enum Issuer
{
    /// <summary>Apple itself signed it: the anchor apple requirement holds.</summary>
    Apple,

    /// <summary>Apple issued the signing certificate: a Developer ID, App Store or Apple development chain.</summary>
    AppleIssued,

    /// <summary>The chain verifies but does not lead to Apple: self-signed or a private CA.</summary>
    NotAppleIssued,

    /// <summary>The issuer check did not answer (it erred or did not finish).</summary>
    Undetermined,
}

/// <param name="AppleQuestionLeftOpen">For an Apple-issued signature with no team, why whether Apple itself signed it is
/// not known; null when it was answered or never asked.</param>
/// <param name="Reason">For <see cref="Issuer.Undetermined"/>, what stopped the issuer check.</param>
public sealed record Issuance(Issuer Issuer, string? AppleQuestionLeftOpen = null, string? Reason = null);

/// <summary>Who stands behind a signature that codesign --verify has already accepted.</summary>
/// <remarks>
/// <para>--verify accepts a self-signed chain, and everything -dvvv prints about it -- the leaf's name, the
/// TeamIdentifier, which is the leaf's OU -- is whatever its maker typed. So a certificate made at home and called
/// "Developer ID Application: Google LLC (EQHXZ8M8AV)" read exactly like Google's. Only a requirement codesign checks
/// against Apple's root tells them apart: anchor apple for Apple's own code, anchor apple generic for any chain Apple
/// issued.</para>
/// <para>Both file_signatures and autostart_audit ask through here, so the two cannot disagree on what is trusted.</para>
/// </remarks>
public static class AppleIssuance
{
    /// <summary>Asks codesign, through <paramref name="codesign"/>, which must report a run that did not finish as a
    /// non-zero exit with its reason on standard error rather than throw.</summary>
    /// <param name="hasTeam">Apple's own code carries no team, so a signature with one skips the anchor apple question: each
    /// requirement check repeats the whole verification, seconds for a large app. A forged team can only cost that
    /// question; the issuer check is asked whatever the team says.</param>
    public static async Task<Issuance> AskAsync(Func<IReadOnlyList<string>, Task<ExternalResult>> codesign, string path, bool hasTeam)
    {
        ArgumentNullException.ThrowIfNull(codesign);
        string? appleLeftOpen = null;
        if (!hasTeam)
        {
            var apple = await codesign(CodesignDisplay.AppleAnchoredArguments(path)).ConfigureAwait(false);
            if (apple.ExitCode == 0)
            {
                // anchor apple implies anchor apple generic; asking would only repeat the verification.
                return new Issuance(Issuer.Apple);
            }

            // 3 is codesign's "requirement not satisfied"; anything else (a timeout is -1) left the question open, and
            // reporting it as not Apple's would be a guess the caller cannot see.
            if (apple.ExitCode != 3)
            {
                appleLeftOpen = Reason(apple, path);
            }
        }

        var issued = await codesign(CodesignDisplay.AppleIssuedArguments(path)).ConfigureAwait(false);
        return issued.ExitCode switch
        {
            0 => new Issuance(Issuer.AppleIssued, appleLeftOpen),
            3 => new Issuance(Issuer.NotAppleIssued),
            _ => new Issuance(Issuer.Undetermined, Reason: Reason(issued, path)),
        };
    }

    /// <summary>The wording for <see cref="Issuer.NotAppleIssued"/>, after "Signed by ...".</summary>
    /// <remarks>The team is left out: printing it beside the name would vouch for the one thing the signer invented.</remarks>
    public const string NotIssuedSuffix =
        ", which Apple did not issue (self-signed or a private CA): its name and team are the signer's own claim";

    /// <summary>The first line of codesign's complaint, without the path it starts by repeating.</summary>
    private static string Reason(ExternalResult result, string path)
    {
        var line = result.StandardError.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0) ?? $"codesign exit {result.ExitCode}";
        return line.StartsWith(path + ": ", StringComparison.Ordinal) ? line[(path.Length + 2)..] : line;
    }
}
