using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WinDiag.Mcp.Diagnostics.Signatures;

/// <summary>
/// Who signed a file, as far as a decision may rest on it: the certificate WinVerifyTrust verified the
/// signature with, never the name picked out of the file's certificate bag.
/// </summary>
/// <remarks>
/// <para>Every trust decision about a signer goes through here -- the update ratchet's publisher pin and
/// the Microsoft check on a Sysinternals binary beside the server -- so they cannot drift apart again.
/// They did: the ratchet moved to <see cref="FileSignature.SignerSubject"/> while the tool locator kept
/// comparing <see cref="FileSignature.Signer"/>, which <c>SelectSigner</c> picks from certificates that
/// sit outside the signed content. A re-signer adds one named "Microsoft Corporation" at will, and a
/// Valid verdict says nothing about it: the verdict is about the certificate that was verified, which
/// could be any CA-issued code-signing certificate.</para>
/// <para><see cref="FileSignature.Signer"/> stays for display -- <c>file_signatures</c> shows it -- and
/// nothing else.</para>
/// </remarks>
public static class VerifiedSigner
{
    /// <summary>The name on the certificate Microsoft signs Sysinternals and its own products with.</summary>
    public const string MicrosoftCorporation = "Microsoft Corporation";

    private const string CommonNameOid = "2.5.4.3";
    private const string OrganizationOid = "2.5.4.10";

    /// <summary>The verified signer's full subject, the identity a publisher is compared by; null when none was verified.</summary>
    public static string? Publisher(FileSignature signature) => signature.SignerSubject;

    /// <summary>
    /// Whether the signature verifies and the certificate it was verified with is Microsoft's own: common
    /// name and organisation both "Microsoft Corporation".
    /// </summary>
    /// <remarks>
    /// The organisation alone is not enough. Microsoft also signs other publishers' components, under its
    /// own organisation, as "Microsoft 3rd Party Application Component", and those are not Sysinternals.
    /// The subject is parsed as a distinguished name, not searched as text: a certificate whose quoted
    /// common name merely contains <c>O=Microsoft Corporation</c> belongs to whoever its real O names.
    /// </remarks>
    public static bool IsMicrosoftCorporation(FileSignature signature) =>
        signature.Verdict == SignatureVerdict.Valid &&
        Names(signature.SignerSubject, MicrosoftCorporation, MicrosoftCorporation);

    /// <summary>
    /// Whether <paramref name="subject"/> has exactly the given common name and organisation, each once.
    /// Anything unparseable, repeated or multi-valued is a no.
    /// </summary>
    internal static bool Names(string? subject, string commonName, string organization)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            return false;
        }

        try
        {
            var commonNames = new List<string>();
            var organizations = new List<string>();
            foreach (var rdn in new X500DistinguishedName(subject).EnumerateRelativeDistinguishedNames())
            {
                if (rdn.HasMultipleElements)
                {
                    return false;
                }

                var value = rdn.GetSingleElementValue();
                switch (rdn.GetSingleElementType().Value)
                {
                    case CommonNameOid:
                        commonNames.Add(value ?? string.Empty);
                        break;
                    case OrganizationOid:
                        organizations.Add(value ?? string.Empty);
                        break;
                }
            }

            return commonNames is [var cn] && string.Equals(cn, commonName, StringComparison.Ordinal) &&
                   organizations is [var o] && string.Equals(o, organization, StringComparison.Ordinal);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
