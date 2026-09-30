using System.Globalization;
using System.Text.Json;

namespace LinuxDiag.Mcp.Linux.Parsers;

/// <param name="Sandbox">A pod's "pause" container, which holds the pod's namespaces and runs nothing of the user's.</param>
public sealed record ContainerdTaskEntry(
    string Namespace, string Id, string? Name, string? Image, string? PodName, string? PodNamespace,
    bool Sandbox, int? InitProcessId);

/// <summary>A containerd v2 task's OCI <c>config.json</c> and <c>init.pid</c>.</summary>
/// <remarks>
/// Read from disk rather than over containerd's gRPC API: that would need a gRPC client and a new
/// dependency for the handful of annotations the CRI plugin already writes into the bundle.
/// </remarks>
public static class ContainerdTask
{
    private const string Prefix = "io.kubernetes.cri.";

    public static ContainerdTaskEntry Parse(string ns, string id, string configJson, string? initPid)
    {
        ArgumentNullException.ThrowIfNull(configJson);

        Dictionary<string, string?> annotations;
        try
        {
            using var document = JsonDocument.Parse(configJson);
            annotations = document.RootElement.TryGetProperty("annotations", out var found) &&
                          found.ValueKind == JsonValueKind.Object
                ? found.EnumerateObject().ToDictionary(
                    p => p.Name, p => p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : null,
                    StringComparer.Ordinal)
                : new Dictionary<string, string?>(StringComparer.Ordinal);
        }
        catch (JsonException ex)
        {
            throw new FormatException($"containerd task {ns}/{id} has an unreadable config.json: {ex.Message}", ex);
        }

        string? Annotation(string key) => annotations.GetValueOrDefault(Prefix + key);

        return new ContainerdTaskEntry(
            ns, id,
            Annotation("container-name"),
            Annotation("image-name"),
            Annotation("sandbox-name"),
            Annotation("sandbox-namespace"),
            Annotation("container-type") == "sandbox",
            int.TryParse(initPid?.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var pid) ? pid : null);
    }
}
