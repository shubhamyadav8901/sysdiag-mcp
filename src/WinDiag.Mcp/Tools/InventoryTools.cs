using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using Diag.Mcp.Server.Files;
using ModelContextProtocol.Server;
using WinDiag.Mcp.Diagnostics.Network;
using WinDiag.Mcp.Diagnostics.Signatures;

namespace WinDiag.Mcp.Tools;

/// <summary>Structured result of <c>network_owners</c>.</summary>
public sealed record NetworkOwnersResult(
    string Summary,
    IReadOnlyList<NetworkEndpoint> Endpoints,
    int TotalMatched,
    bool Truncated);

/// <summary>Structured result of <c>file_signatures</c>.</summary>
public sealed record FileSignaturesResult(
    string Summary,
    IReadOnlyList<FileSignature> Files,
    IReadOnlyList<string> NotFound);

/// <summary>Who owns which socket, and is this binary the one we shipped.</summary>
[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class InventoryTools
{
    private readonly INetworkInspector _network;
    private readonly ISignatureInspector _signatures;
    private readonly FileTransferOptions _files;

    public InventoryTools(INetworkInspector network, ISignatureInspector signatures, FileTransferOptions files)
    {
        _network = network;
        _signatures = signatures;
        _files = files;
    }

    [McpServerTool(
        Name = "network_owners",
        Title = "Network endpoints and owning processes",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "List local TCP and UDP endpoints (IPv4 and IPv6) with the process that owns each one. Use it " +
        "for 'what is already using port 8080', 'which process is talking to that address', or to " +
        "confirm a service is actually listening where it should be. Filter by port, by owning PID, or " +
        "to listening endpoints only.")]
    public NetworkOwnersResult NetworkOwners(
        [Description("Only endpoints using this local or remote port")]
        int? port = null,
        [Description("Only endpoints owned by this process id")]
        int? processId = null,
        [Description("Only listening TCP sockets and bound UDP endpoints, excluding established connections")]
        bool listeningOnly = false,
        CancellationToken cancellationToken = default)
    {
        var result = _network.List(port, processId, listeningOnly, cancellationToken);

        return new NetworkOwnersResult(
            RenderEndpoints(result, port, processId, listeningOnly),
            result.Endpoints,
            result.TotalMatched,
            result.Truncated);
    }

    [McpServerTool(
        Name = "file_signatures",
        Title = "File signature and version",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = true,
        UseStructuredContent = true)]
    [Description(
        "Verify Authenticode trust for one or more files and report their version, company, size, " +
        "modification time and SHA-256. Use it to confirm a deployed binary is the version and build " +
        "you shipped, to spot a file that was modified after signing, or to identify an unsigned DLL " +
        "loaded into a process. Correctly handles catalog-signed Windows binaries, which carry no " +
        "certificate inside the file.")]
    public FileSignaturesResult FileSignatures(
        [Description("Full paths of the files to inspect")]
        string[] paths,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(paths);

        if (paths.Length == 0)
        {
            throw new ArgumentException("Provide at least one file path.", nameof(paths));
        }

        // Every path is checked before any is inspected, so a refused call has opened nothing at all.
        foreach (var path in paths)
        {
            LocalPathGuard.RequireLocal(path, nameof(paths), _files);
        }

        var result = _signatures.Inspect(paths, cancellationToken);

        return new FileSignaturesResult(RenderSignatures(result), result.Files, result.NotFound);
    }

    internal static string RenderEndpoints(
        NetworkEndpointsResult result,
        int? port,
        int? processId,
        bool listeningOnly)
    {
        var builder = new StringBuilder();

        if (result.Endpoints.Count == 0)
        {
            builder.Append("No ").Append(listeningOnly ? "listening endpoint" : "endpoint").Append(" matched");
            if (port is { } p)
            {
                builder.Append(" port ").Append(p);
            }

            if (processId is { } pid)
            {
                builder.Append(" PID ").Append(pid);
            }

            builder.Append('.');

            if (port is not null)
            {
                // The useful reading of an empty port query: nothing holds it, so a bind failure has a
                // different cause (permissions, a reserved range, or the wrong interface).
                builder.Append(" Nothing is bound to that port, so a bind failure there is not a conflict ")
                    .Append("with another process.");
            }

            return builder.ToString();
        }

        builder.Append(result.TotalMatched)
            .Append(result.TotalMatched == 1 ? " endpoint" : " endpoints").AppendLine(":");

        foreach (var endpoint in result.Endpoints.Take(RenderLimits.MaxRenderedRows))
        {
            builder.Append("- ").Append(endpoint.Protocol.ToString().ToUpperInvariant()).Append(' ')
                .Append(Format(endpoint.LocalAddress, endpoint.LocalPort));

            if (endpoint.RemotePort is { } remotePort && endpoint.RemoteAddress is { } remoteAddress)
            {
                builder.Append(" -> ").Append(Format(remoteAddress, remotePort));
            }

            if (endpoint.State is { } state)
            {
                builder.Append(" [").Append(state).Append(']');
            }

            builder.Append(" owned by ").Append(endpoint.ProcessName ?? "(unknown process)")
                .Append(" (PID ").Append(endpoint.OwningProcessId).Append(')');

            builder.AppendLine();
        }

        RenderLimits.NoteElision(builder, result.Endpoints.Count, "returned endpoints");

        if (result.Truncated)
        {
            builder.Append("Showing the first ").Append(result.Endpoints.Count).Append(" of ")
                .Append(result.TotalMatched).Append("; narrow the filter or raise WINDIAG_MAX_RESULTS.");
        }

        return builder.ToString().TrimEnd();
    }

    internal static string RenderSignatures(SignatureQueryResult result)
    {
        var builder = new StringBuilder();

        foreach (var missing in result.NotFound)
        {
            builder.Append("NOT FOUND: ").AppendLine(missing);
        }

        foreach (var file in result.Files)
        {
            builder.Append(file.Path).AppendLine();
            builder.Append("  ").Append(file.Verdict.ToString().ToUpperInvariant()).Append(" - ")
                .AppendLine(file.Detail);

            if (file.CatalogSigned)
            {
                builder.AppendLine("  Trust comes from a system catalog; the file carries no embedded certificate.");
            }

            if (file.Signer is { } signer)
            {
                builder.Append("  Signer: ").Append(signer);
                if (file.Issuer is { } issuer)
                {
                    builder.Append(" (issued by ").Append(issuer).Append(')');
                }

                if (file.CertificateNotAfter is { } notAfter)
                {
                    builder.Append(", certificate valid to ")
                        .Append(notAfter.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
                }

                builder.AppendLine();
            }

            builder.Append("  Version: ").Append(file.FileVersion ?? "(none)");
            if (file.ProductVersion is { } product && product != file.FileVersion)
            {
                builder.Append(" (product ").Append(product).Append(')');
            }

            if (file.CompanyName is { } company)
            {
                builder.Append(", ").Append(company);
            }

            builder.AppendLine();

            if (file.OriginalFilename is { } original
                && !string.Equals(original, Path.GetFileName(file.Path), StringComparison.OrdinalIgnoreCase))
            {
                // A mismatch here means the file was renamed after build, which is worth noticing when
                // chasing a DLL that is not the one you think it is.
                builder.Append("  Original filename was '").Append(original)
                    .AppendLine("', so this file has been renamed.");
            }

            builder.Append("  ").Append(file.SizeBytes.ToString("N0", CultureInfo.InvariantCulture))
                .Append(" bytes, modified ")
                .Append(file.LastWriteTime.ToString("u", CultureInfo.InvariantCulture)).AppendLine();
            builder.Append("  SHA-256: ").AppendLine(file.Sha256);
        }

        return builder.ToString().TrimEnd();
    }

    private static string Format(string address, int port) =>
        address.Contains(':') ? $"[{address}]:{port}" : $"{address}:{port}";
}
