using WinDiag.Mcp.Diagnostics.Capabilities;
using WinDiag.Mcp.Diagnostics.External;
using WinDiag.Mcp.Diagnostics.Signatures;

namespace WinDiag.Mcp.Tests;

/// <summary>A Sysinternals binary found beside the server runs only when Microsoft signed it.</summary>
/// <remarks>
/// The server's own folder is searched before any installed copy, and what is found there runs as the
/// service's account. A file planted there -- by put_file, before it needed the self-update grant, or by
/// anyone else who can write that folder -- turned the next path_handle_search into code execution as
/// SYSTEM. The PE bitness check was the only thing standing between the two.
/// </remarks>
public sealed class ToolLocatorSignatureTests : IDisposable
{
    private readonly string _serverDirectory = Directory.CreateTempSubdirectory("windiag-locator-sig").FullName;

    public void Dispose() => Directory.Delete(_serverDirectory, recursive: true);

    private string Plant(string name)
    {
        var path = Path.Combine(_serverDirectory, name);
        File.WriteAllText(path, "planted");
        return path;
    }

    private static FileSignature Signature(string path, SignatureVerdict verdict, string? signer) =>
        new(path, verdict, "detail from the fake", false, signer, null, null, null, null, null, null, 7,
            DateTimeOffset.UnixEpoch, "00");

    /// <summary>Answers every path with whatever <see cref="Next"/> says at the time of the call.</summary>
    private sealed class FakeSignatures : ISignatureInspector
    {
        public (SignatureVerdict Verdict, string? Signer) Next { get; set; } = (SignatureVerdict.Valid, "Microsoft Corporation");

        public List<string> Inspected { get; } = [];

        public SignatureQueryResult Inspect(IReadOnlyList<string> paths, CancellationToken cancellationToken)
        {
            Inspected.AddRange(paths);
            return new SignatureQueryResult([.. paths.Select(p => Signature(p, Next.Verdict, Next.Signer))], []);
        }
    }

    [Fact]
    public void A_Microsoft_signed_tool_beside_the_server_is_used()
    {
        var planted = Plant("handle64.exe");
        var locator = new ToolLocator(new FakeSignatures(), _serverDirectory);

        Assert.True(locator.TryResolve("handle64.exe", out var path));
        Assert.Equal(planted, path);
    }

    [Theory]
    [InlineData(SignatureVerdict.Unsigned, null)]
    [InlineData(SignatureVerdict.Untrusted, "Microsoft Corporation")]
    [InlineData(SignatureVerdict.Valid, "Contoso Ltd")]
    [InlineData(SignatureVerdict.Unknown, null)]
    public void A_tool_beside_the_server_that_Microsoft_did_not_sign_is_refused_with_the_reason(
        SignatureVerdict verdict, string? signer)
    {
        // Refused, not skipped: falling through to "not installed" would send the operator looking for a
        // missing file that is sitting right there, and an installed copy elsewhere would quietly mask
        // a folder someone has tampered with.
        var planted = Plant("handle64.exe");
        var locator = new ToolLocator(new FakeSignatures { Next = (verdict, signer) }, _serverDirectory);

        var resolve = Assert.Throws<UntrustedToolException>(() => locator.Resolve("handle64.exe"));
        var tryResolve = Assert.Throws<UntrustedToolException>(() => locator.TryResolve("handle64.exe", out _));

        Assert.Contains(planted, resolve.Message, StringComparison.Ordinal);
        Assert.Contains("not signed by Microsoft", resolve.Message, StringComparison.Ordinal);
        Assert.Equal(resolve.Message, tryResolve.Message);
    }

    [Fact]
    public void A_tool_replaced_beside_the_server_after_it_was_resolved_is_checked_again()
    {
        // A cached success would keep running the path it first approved, whatever is there now.
        Plant("handle64.exe");
        var signatures = new FakeSignatures();
        var locator = new ToolLocator(signatures, _serverDirectory);
        Assert.True(locator.TryResolve("handle64.exe", out _));

        signatures.Next = (SignatureVerdict.Unsigned, null);

        Assert.Throws<UntrustedToolException>(() => locator.Resolve("handle64.exe"));
    }

    [Fact]
    public void Capabilities_report_the_refusal_rather_than_a_missing_tool()
    {
        var planted = Plant(SysinternalsArchitecture.PreferredFileName("handle"));
        var locator = new ToolLocator(new FakeSignatures { Next = (SignatureVerdict.Unsigned, null) }, _serverDirectory);

        var resolution = new SysinternalsExecutableResolver(locator).Resolve("handle");

        Assert.Null(resolution.Path);
        Assert.Contains(planted, resolution.Problem, StringComparison.Ordinal);
        Assert.Contains("not signed by Microsoft", resolution.Problem, StringComparison.Ordinal);
    }
}
