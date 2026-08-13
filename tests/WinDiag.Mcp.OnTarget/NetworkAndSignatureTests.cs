using System.Net;
using System.Net.Sockets;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics.Network;
using WinDiag.Mcp.Diagnostics.Signatures;
using Xunit.Abstractions;

namespace WinDiag.Mcp.OnTarget;

/// <summary>
/// Validates the IP Helper interop against a socket this test opens itself.
/// </summary>
/// <remarks>
/// Port numbers live in network byte order inside these structures. Reading them without swapping
/// yields values like 20480 for port 80 -- plausible-looking high ports rather than an obvious error,
/// which no unit test over canned data would catch. Binding a real socket and reading its port back is
/// the only check that actually proves the conversion.
/// </remarks>
[Trait("Category", "OnTarget")]
public sealed class NetworkInspectorTests(ITestOutputHelper output)
{
    private static INetworkInspector Inspector() => new IpHelperNetworkInspector(new WinDiagOptions());

    [Fact]
    public void Finds_a_listening_socket_this_test_opened_with_the_correct_port_and_owner()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            output.WriteLine($"listening on {port}, PID {Environment.ProcessId}");

            var result = Inspector().List(port, null, listeningOnly: false, CancellationToken.None);

            var endpoint = Assert.Single(
                result.Endpoints,
                e => e.OwningProcessId == Environment.ProcessId && e.LocalPort == port);

            Assert.Equal(TransportProtocol.Tcp, endpoint.Protocol);
            Assert.Equal("Listen", endpoint.State);
            Assert.Equal(IPAddress.Loopback.ToString(), endpoint.LocalAddress);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public void Finds_a_bound_udp_endpoint_with_the_correct_port()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)socket.LocalEndPoint!).Port;

        var result = Inspector().List(port, null, listeningOnly: false, CancellationToken.None);

        var endpoint = Assert.Single(
            result.Endpoints,
            e => e.OwningProcessId == Environment.ProcessId && e.LocalPort == port);

        Assert.Equal(TransportProtocol.Udp, endpoint.Protocol);
        Assert.Null(endpoint.State);
    }

    [Fact]
    public void Enumerates_the_machine_wide_table_not_just_this_process()
    {
        var all = Inspector().List(null, null, listeningOnly: false, CancellationToken.None);

        output.WriteLine($"{all.TotalMatched} endpoints across " +
                         $"{all.Endpoints.Select(e => e.OwningProcessId).Distinct().Count()} processes");

        Assert.True(all.TotalMatched > 5, $"only {all.TotalMatched} endpoints found");
        Assert.Contains(all.Endpoints, e => e.OwningProcessId != Environment.ProcessId);
    }

    [Fact]
    public void Reports_nothing_bound_to_a_port_that_is_genuinely_free()
    {
        // Reserve a port, learn its number, release it. Nothing should own it afterwards.
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var freed = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        var result = Inspector().List(freed, null, listeningOnly: false, CancellationToken.None);

        Assert.DoesNotContain(result.Endpoints, e => e.LocalPort == freed && e.State == "Listen");
    }
}

/// <summary>
/// Validates Authenticode verification against files whose trust status is known.
/// </summary>
[Trait("Category", "OnTarget")]
public sealed class SignatureInspectorTests(ITestOutputHelper output)
{
    private static ISignatureInspector Inspector() => new WinTrustSignatureInspector();

    [Fact]
    public void Trusts_a_windows_system_binary()
    {
        var path = Path.Combine(Environment.SystemDirectory, "kernel32.dll");

        var file = Assert.Single(Inspector().Inspect([path], CancellationToken.None).Files);

        output.WriteLine($"{file.Verdict}: {file.Detail} (catalog={file.CatalogSigned}, signer={file.Signer})");

        Assert.Equal(SignatureVerdict.Valid, file.Verdict);
        Assert.Equal("Microsoft Corporation", file.CompanyName);
        Assert.NotNull(file.FileVersion);
        Assert.Equal(64, file.Sha256.Length);
    }

    [Fact]
    public void Reports_catalog_signing_consistently_across_a_sample_of_system_binaries()
    {
        // Deliberately not asserting that a NAMED file is catalog-signed. Which System32 binaries carry
        // an embedded signature versus only a catalog entry varies by Windows build -- kernel32.dll is
        // embedded-signed here -- so pinning one filename tests the machine, not the code.
        //
        // What must hold on every build is the invariant: CatalogSigned means trusted with no embedded
        // certificate, and nothing else.
        var directory = Environment.SystemDirectory;
        var sample = Directory.EnumerateFiles(directory, "*.dll")
            .Take(40)
            .Concat(Directory.EnumerateFiles(directory, "*.exe").Take(20))
            .ToArray();

        var result = Inspector().Inspect(sample, CancellationToken.None);

        foreach (var file in result.Files)
        {
            Assert.Equal(file.Verdict == SignatureVerdict.Valid && file.Signer is null, file.CatalogSigned);
        }

        var catalogSigned = result.Files.Count(f => f.CatalogSigned);
        var embeddedSigned = result.Files.Count(f => f.Verdict == SignatureVerdict.Valid && f.Signer is not null);
        output.WriteLine($"{result.Files.Count} sampled: {catalogSigned} catalog-signed, {embeddedSigned} embedded-signed");

        foreach (var group in result.Files.GroupBy(f => f.Verdict))
        {
            output.WriteLine($"  {group.Key}: {group.Count()} e.g. {Path.GetFileName(group.First().Path)}");
        }

        // Both attribution paths must be exercised by a System32 sample. Zero embedded-signed means
        // certificate reading is broken; zero catalog-signed means catalog lookup is broken -- and the
        // latter failed silently as "Unsigned" for 38 of these 60 files until WINTRUST_CATALOG_INFO
        // carried the catalog admin context.
        Assert.True(embeddedSigned > 0, "no embedded-signed binaries found; certificate reading is broken");
        Assert.True(catalogSigned > 0, "no catalog-signed binaries found; catalog verification is broken");

        // Nothing in a healthy System32 should be reported as having no signature at all.
        var unsigned = result.Files.Where(f => f.Verdict == SignatureVerdict.Unsigned).ToArray();
        Assert.True(
            unsigned.Length == 0,
            $"{unsigned.Length} System32 binaries reported as unsigned, e.g. {Path.GetFileName(unsigned.FirstOrDefault()?.Path ?? "")}");
    }

    [Fact]
    public void Names_the_signer_of_a_binary_with_an_embedded_signature()
    {
        // The counterpart to the catalog case, and the regression guard for a subtle failure: reading
        // the certificate with an API that rejects Authenticode content throws for every signed
        // binary, which makes every file look catalog-signed with an unknown signer. Nothing else in
        // the suite would notice.
        var path = Environment.ProcessPath ?? Path.Combine(Environment.SystemDirectory, "kernel32.dll");

        var file = Assert.Single(Inspector().Inspect([path], CancellationToken.None).Files);

        output.WriteLine($"{path}: verdict={file.Verdict}, catalog={file.CatalogSigned}, signer={file.Signer}");

        if (file.Verdict != SignatureVerdict.Valid)
        {
            Assert.Fail($"expected a validly signed host binary, got {file.Verdict}: {file.Detail}");
        }

        Assert.False(file.CatalogSigned, "an embedded-signed binary must not be reported as catalog-signed");
        Assert.NotNull(file.Signer);
        Assert.NotNull(file.Issuer);
        Assert.NotNull(file.CertificateNotAfter);
    }

    [Fact]
    public void Reports_an_ordinary_file_as_unsigned_rather_than_as_a_failure()
    {
        var path = Path.Combine(Path.GetTempPath(), $"windiag-unsigned-{Guid.NewGuid():N}.txt");
        File.WriteAllText(path, "not a signed binary");

        try
        {
            var file = Assert.Single(Inspector().Inspect([path], CancellationToken.None).Files);

            Assert.Equal(SignatureVerdict.Unsigned, file.Verdict);
            Assert.False(file.CatalogSigned);
            Assert.Null(file.Signer);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Detects_a_signed_binary_that_was_modified_after_signing()
    {
        // The security-relevant case: a trusted file whose contents no longer match its signature must
        // never come back as Valid.
        var source = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        if (!File.Exists(source))
        {
            source = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
        }

        var tampered = Path.Combine(Path.GetTempPath(), $"windiag-tampered-{Guid.NewGuid():N}.exe");
        File.Copy(source, tampered);

        try
        {
            // Flip bytes in the middle of the image, well past the headers.
            using (var stream = new FileStream(tampered, FileMode.Open, FileAccess.ReadWrite))
            {
                stream.Seek(stream.Length / 2, SeekOrigin.Begin);
                stream.Write([0xDE, 0xAD, 0xBE, 0xEF]);
            }

            var file = Assert.Single(Inspector().Inspect([tampered], CancellationToken.None).Files);

            output.WriteLine($"{file.Verdict}: {file.Detail}");

            Assert.NotEqual(SignatureVerdict.Valid, file.Verdict);
        }
        finally
        {
            File.Delete(tampered);
        }
    }

    [Fact]
    public void Separates_missing_files_from_inspected_ones()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"windiag-absent-{Guid.NewGuid():N}.exe");

        var result = Inspector().Inspect(
            [Path.Combine(Environment.SystemDirectory, "kernel32.dll"), missing], CancellationToken.None);

        Assert.Single(result.Files);
        Assert.Single(result.NotFound);
        Assert.Equal(missing, result.NotFound[0]);
    }
}
