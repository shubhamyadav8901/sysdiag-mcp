using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WinDiag.Mcp.Diagnostics.Signatures;

/// <summary>
/// Verifies Authenticode trust with <c>WinVerifyTrust</c> and reads identity from the file itself.
/// </summary>
/// <remarks>
/// <para><c>WinVerifyTrust</c> rather than <c>X509Certificate.CreateFromSignedFile</c>, because the
/// latter only sees signatures embedded in the file. The majority of Windows' own binaries are signed
/// by <em>catalog</em>, with no certificate inside them, so an embedded-only check reports half of
/// <c>System32</c> as unsigned -- an alarming and completely wrong answer.</para>
/// <para>The embedded certificate is still read when present, to name the signer, but the trust
/// verdict always comes from WinVerifyTrust.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WinTrustSignatureInspector : ISignatureInspector
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdChoiceCatalog = 2;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;

    private const int TrustEOk = 0;
    private const int TrustENosignature = unchecked((int)0x800B0100);
    private const int TrustEBadDigest = unchecked((int)0x80096010);
    private const int CertEExpired = unchecked((int)0x800B0101);
    private const int CertEUntrustedroot = unchecked((int)0x800B0109);
    private const int CertEChaining = unchecked((int)0x800B010A);
    private const int TrustEExplicitDistrust = unchecked((int)0x800B0111);
    private const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);

    public SignatureQueryResult Inspect(IReadOnlyList<string> paths, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(paths);

        var files = new List<FileSignature>();
        var notFound = new List<string>();

        foreach (var path in paths)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string full;
            try
            {
                full = Path.GetFullPath(path);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                notFound.Add(path);
                continue;
            }

            if (!File.Exists(full))
            {
                notFound.Add(full);
                continue;
            }

            files.Add(Describe(full));
        }

        return new SignatureQueryResult(files, notFound);
    }

    private static FileSignature Describe(string path)
    {
        var (verdict, detail, catalogSigned) = VerifyEmbeddedThenCatalog(path);
        var info = FileVersionInfo.GetVersionInfo(path);
        var file = new FileInfo(path);
        using var certificate = ReadEmbeddedCertificate(path);

        return new FileSignature(
            Path: path,
            Verdict: verdict,
            Detail: detail,
            CatalogSigned: catalogSigned,
            Signer: certificate?.GetNameInfo(X509NameType.SimpleName, forIssuer: false),
            Issuer: certificate?.GetNameInfo(X509NameType.SimpleName, forIssuer: true),
            CertificateNotAfter: certificate is null ? null : new DateTimeOffset(certificate.NotAfter),
            FileVersion: NullIfEmpty(info.FileVersion),
            ProductVersion: NullIfEmpty(info.ProductVersion),
            CompanyName: NullIfEmpty(info.CompanyName),
            OriginalFilename: NullIfEmpty(info.OriginalFilename),
            SizeBytes: file.Length,
            LastWriteTime: new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero),
            Sha256: ComputeSha256(path));

        static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
    }

    /// <summary>
    /// Verifies the embedded signature, then the system catalogs if there is no embedded signature.
    /// </summary>
    /// <remarks>
    /// <para><strong>Both passes are required.</strong> <c>WTD_CHOICE_FILE</c> only ever examines a
    /// signature embedded in the file; it does not consult catalogs, whatever the name
    /// "generic verify" suggests. Measured on this machine: of 60 sampled binaries in System32, 22
    /// carry embedded signatures and <em>38 -- every one of them a genuine, trusted Microsoft
    /// binary -- come back as TRUST_E_NOSIGNATURE</em> from the file pass alone.</para>
    /// <para>Reporting those as unsigned would be the single worst failure this tool could have: the
    /// question it exists to answer is "is this the binary we shipped", and a confident false
    /// "unsigned" on ordinary Windows DLLs poisons every conclusion drawn from it.</para>
    /// </remarks>
    private static (SignatureVerdict Verdict, string Detail, bool CatalogSigned) VerifyEmbeddedThenCatalog(string path)
    {
        var (verdict, detail, status) = Verify(path);

        if (status != TrustENosignature && status != TrustESubjectFormUnknown)
        {
            return (verdict, detail, false);
        }

        var catalog = VerifyViaCatalog(path);
        if (catalog is not { } result)
        {
            return (verdict, detail, false);
        }

        return (Classify(result.Status),
            result.Status == TrustEOk
                ? $"Signature is present and trusted, via the system catalog {result.CatalogFile}."
                : Explain(result.Status),
            result.Status == TrustEOk);
    }

    /// <summary>
    /// Looks the file's hash up in the system catalogs and verifies the catalog entry, if one exists.
    /// </summary>
    /// <returns>Null when the file is in no catalog, which means it genuinely has no signature.</returns>
    private static (int Status, string CatalogFile)? VerifyViaCatalog(string path)
    {
        using var stream = TryOpenRead(path);
        if (stream is null)
        {
            return null;
        }

        var fileHandle = stream.SafeFileHandle.DangerousGetHandle();

        if (!CryptCATAdminAcquireContext2(out var adminContext, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
        {
            return null;
        }

        try
        {
            uint hashLength = 0;
            if (!CryptCATAdminCalcHashFromFileHandle2(adminContext, fileHandle, ref hashLength, null, 0)
                && hashLength == 0)
            {
                return null;
            }

            var hash = new byte[hashLength];
            if (!CryptCATAdminCalcHashFromFileHandle2(adminContext, fileHandle, ref hashLength, hash, 0))
            {
                return null;
            }

            var catalogContext = CryptCATAdminEnumCatalogFromHash(adminContext, hash, hashLength, 0, IntPtr.Zero);
            if (catalogContext == IntPtr.Zero)
            {
                // Not in any catalog, and no embedded signature either: genuinely unsigned.
                return null;
            }

            try
            {
                var info = new CatalogInfo { cbStruct = (uint)Marshal.SizeOf<CatalogInfo>() };
                if (!CryptCATCatalogInfoFromContext(catalogContext, ref info, 0))
                {
                    return null;
                }

                return (VerifyCatalogMember(adminContext, info.wszCatalogFile, path, hash, fileHandle),
                    info.wszCatalogFile);
            }
            finally
            {
                CryptCATAdminReleaseCatalogContext(adminContext, catalogContext, 0);
            }
        }
        finally
        {
            CryptCATAdminReleaseContext(adminContext, 0);
        }
    }

    /// <summary>Verifies one member of a catalog.</summary>
    /// <remarks>
    /// <para><paramref name="adminContext"/> must be passed through into
    /// <c>WINTRUST_CATALOG_INFO.hCatAdmin</c>. This is not optional bookkeeping: measured on this
    /// machine against a SHA-256 catalog context,</para>
    /// <code>
    /// hCatAdmin = 0            -> 0x800B0100 TRUST_E_NOSIGNATURE
    /// hCatAdmin = adminContext -> 0x00000000 S_OK
    /// </code>
    /// <para>Leaving it null makes every catalog-signed file -- most of Windows -- report as unsigned,
    /// with no error to indicate anything went wrong. A SHA-1 context happens to succeed without it,
    /// which is exactly why the omission survives casual testing.</para>
    /// </remarks>
    private static int VerifyCatalogMember(
        IntPtr adminContext, string catalogFile, string path, byte[] hash, IntPtr fileHandle)
    {
        // The member tag is the file hash as an uppercase hex string; that is how the entry is named
        // inside the catalog.
        var memberTag = Convert.ToHexString(hash);

        var hashHandle = GCHandle.Alloc(hash, GCHandleType.Pinned);
        var catalogInfo = new WintrustCatalogInfo
        {
            cbStruct = (uint)Marshal.SizeOf<WintrustCatalogInfo>(),
            pcwszCatalogFilePath = Marshal.StringToCoTaskMemUni(catalogFile),
            pcwszMemberTag = Marshal.StringToCoTaskMemUni(memberTag),
            pcwszMemberFilePath = Marshal.StringToCoTaskMemUni(path),
            hMemberFile = fileHandle,
            pbCalculatedFileHash = hashHandle.AddrOfPinnedObject(),
            cbCalculatedFileHash = (uint)hash.Length,
            hCatAdmin = adminContext
        };

        var catalogInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WintrustCatalogInfo>());
        Marshal.StructureToPtr(catalogInfo, catalogInfoPtr, false);

        var data = new WintrustData
        {
            cbStruct = (uint)Marshal.SizeOf<WintrustData>(),
            dwUIChoice = WtdUiNone,
            fdwRevocationChecks = WtdRevokeNone,
            dwUnionChoice = WtdChoiceCatalog,
            pFile = catalogInfoPtr,
            dwStateAction = WtdStateActionVerify,
            dwProvFlags = WtdCacheOnlyUrlRetrieval
        };

        var guid = GenericVerifyV2;

        try
        {
            var status = WinVerifyTrust(IntPtr.Zero, ref guid, ref data);

            data.dwStateAction = WtdStateActionClose;
            WinVerifyTrust(IntPtr.Zero, ref guid, ref data);

            return status;
        }
        finally
        {
            Marshal.FreeCoTaskMem(catalogInfo.pcwszCatalogFilePath);
            Marshal.FreeCoTaskMem(catalogInfo.pcwszMemberTag);
            Marshal.FreeCoTaskMem(catalogInfo.pcwszMemberFilePath);
            Marshal.FreeCoTaskMem(catalogInfoPtr);
            hashHandle.Free();
        }
    }

    private static FileStream? TryOpenRead(string path)
    {
        try
        {
            return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Runs WinVerifyTrust against the file's embedded signature only.</summary>
    internal static (SignatureVerdict Verdict, string Detail, int Status) Verify(string path)
    {
        var fileInfo = new WintrustFileInfo
        {
            cbStruct = (uint)Marshal.SizeOf<WintrustFileInfo>(),
            pcwszFilePath = Marshal.StringToCoTaskMemUni(path)
        };

        var fileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WintrustFileInfo>());
        Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

        var data = new WintrustData
        {
            cbStruct = (uint)Marshal.SizeOf<WintrustData>(),
            dwUIChoice = WtdUiNone,
            fdwRevocationChecks = WtdRevokeNone,
            dwUnionChoice = WtdChoiceFile,
            pFile = fileInfoPtr,
            dwStateAction = WtdStateActionVerify,

            // No network round trip for revocation: this runs on a possibly-isolated target machine,
            // and a stalled CRL fetch would turn a fast local check into a timeout.
            dwProvFlags = WtdCacheOnlyUrlRetrieval
        };

        var guid = GenericVerifyV2;

        try
        {
            var status = WinVerifyTrust(IntPtr.Zero, ref guid, ref data);

            data.dwStateAction = WtdStateActionClose;
            WinVerifyTrust(IntPtr.Zero, ref guid, ref data);

            return (Classify(status), Explain(status), status);
        }
        finally
        {
            Marshal.FreeCoTaskMem(fileInfo.pcwszFilePath);
            Marshal.FreeCoTaskMem(fileInfoPtr);
        }
    }

    private static SignatureVerdict Classify(int status) => status switch
    {
        TrustEOk => SignatureVerdict.Valid,
        TrustENosignature or TrustESubjectFormUnknown => SignatureVerdict.Unsigned,
        TrustEBadDigest or CertEExpired or CertEUntrustedroot or CertEChaining or TrustEExplicitDistrust
            => SignatureVerdict.Untrusted,
        _ => SignatureVerdict.Unknown
    };

    private static string Explain(int status) => status switch
    {
        TrustEOk => "Signature is present and trusted.",
        TrustENosignature or TrustESubjectFormUnknown =>
            "No Authenticode signature, embedded or by catalog.",
        TrustEBadDigest =>
            "SIGNATURE DOES NOT MATCH THE FILE CONTENTS - the file was modified after it was signed.",
        CertEExpired => "Signed, but the signing certificate has expired.",
        CertEUntrustedroot => "Signed, but the certificate chains to a root this machine does not trust.",
        CertEChaining => "Signed, but the certificate chain could not be built.",
        TrustEExplicitDistrust => "Signed by a certificate that is explicitly distrusted on this machine.",
        _ => $"Verification did not complete (HRESULT 0x{status:X8})."
    };

    /// <summary>
    /// Reads the certificate embedded in the file, if any.
    /// </summary>
    /// <remarks>
    /// Absence is not evidence of anything on its own: catalog-signed files are trusted without
    /// carrying a certificate. That is why the verdict comes from WinVerifyTrust and this only supplies
    /// the signer's name when one happens to be present.
    /// </remarks>
    private static X509Certificate2? ReadEmbeddedCertificate(string path)
    {
        // X509CertificateLoader looks deliberately right here and is completely wrong: it only accepts
        // content type Cert, whereas a signed PE is Authenticode, so it throws for EVERY signed binary.
        // The failure is silent and inverted -- every properly signed file would be reported as having
        // no certificate, and therefore as catalog-signed.
        //
        // X509Certificate2Collection.Import does understand Authenticode. The signer is the first
        // certificate in the returned collection.
        try
        {
            var collection = new X509Certificate2Collection();

            // SYSLIB0057 tells us to use X509CertificateLoader instead. We cannot: that is precisely
            // the API that rejects Authenticode content, which is the only content type that matters
            // here. Suppressed deliberately rather than followed into a silent wrong answer.
#pragma warning disable SYSLIB0057
            collection.Import(path);
#pragma warning restore SYSLIB0057

            return SelectSigner(collection);
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
        {
            // No embedded signature, or the file is held exclusively by another process -- which is a
            // routine case for this tool, since it is often pointed at a DLL loaded somewhere else.
            // Neither justifies failing the whole batch.
            return null;
        }
    }

    /// <summary>
    /// Picks the signing (leaf) certificate out of an imported chain.
    /// </summary>
    /// <remarks>
    /// Import returns the whole chain, and the leaf is not reliably first: taking <c>collection[0]</c>
    /// yields an intermediate CA, so the tool reports the signer of a Microsoft binary as
    /// "Microsoft Windows Production PCA 2011" -- a real certificate, wrong answer, and one that looks
    /// plausible enough to go unquestioned.
    /// <para>The leaf is the certificate that issued nothing else in the chain.</para>
    /// </remarks>
    internal static X509Certificate2? SelectSigner(X509Certificate2Collection collection)
    {
        if (collection.Count == 0)
        {
            return null;
        }

        X509Certificate2? leaf = null;

        foreach (var candidate in collection)
        {
            var issuedSomethingElse = collection
                .Any(other => !ReferenceEquals(other, candidate)
                              && string.Equals(other.IssuerName.Name, candidate.SubjectName.Name,
                                  StringComparison.OrdinalIgnoreCase));

            if (!issuedSomethingElse)
            {
                leaf = candidate;
                break;
            }
        }

        leaf ??= collection[0];

        // Everything except the returned certificate is ours to release.
        foreach (var certificate in collection)
        {
            if (!ReferenceEquals(certificate, leaf))
            {
                certificate.Dispose();
            }
        }

        return leaf;
    }

    private static string ComputeSha256(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return "(unreadable)";
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WintrustData pWVTData);

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustCatalogInfo
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint cbStruct;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr phCatAdmin,
        IntPtr pgSubsystem,
        [MarshalAs(UnmanagedType.LPWStr)] string pwszHashAlgorithm,
        IntPtr pStrongHashPolicy,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(
        IntPtr hCatInfo, ref CatalogInfo psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
}
