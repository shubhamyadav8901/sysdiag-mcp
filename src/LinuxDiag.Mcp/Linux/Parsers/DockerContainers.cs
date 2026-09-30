using System.Text.Json;

namespace LinuxDiag.Mcp.Linux.Parsers;

public sealed record DockerContainer(string Id, string? Name, string? Image, string? State);

/// <summary>Docker Engine's <c>GET /containers/json</c> answer.</summary>
public static class DockerContainers
{
    public static IReadOnlyList<DockerContainer> Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                throw new FormatException($"Docker's container list was not a JSON array: {Excerpt(json)}");
            }

            var containers = new List<DockerContainer>();
            foreach (var container in document.RootElement.EnumerateArray())
            {
                var id = Text(container, "Id") ?? throw new FormatException("A Docker container had no Id.");

                // Names carries the leading '/' of Docker's old link namespace.
                string? name = null;
                if (container.TryGetProperty("Names", out var names) &&
                    names.ValueKind == JsonValueKind.Array && names.GetArrayLength() > 0)
                {
                    name = names[0].GetString()?.TrimStart('/');
                }

                containers.Add(new DockerContainer(id, name, Text(container, "Image"), Text(container, "State")));
            }

            return containers;
        }
        catch (JsonException ex)
        {
            throw new FormatException($"Docker's container list was not valid JSON: {ex.Message}", ex);
        }
    }

    internal static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string Excerpt(string text) => text.Length <= 120 ? text : text[..120] + "...";
}
