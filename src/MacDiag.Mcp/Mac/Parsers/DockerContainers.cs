using System.Text.Json;

namespace MacDiag.Mcp.Mac.Parsers;

public sealed record DockerContainer(string Id, string? Name, string? Image, string? State);

/// <summary>Docker Engine's GET /containers/json: an array, each with an Id, Names, Image and State.</summary>
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
                // Never an excerpt: between the checks and the connect, a home's owner can swap the socket for a link to a
                // root-only one, and what that socket says must not come back to the caller.
                throw new FormatException($"Docker's container list was a JSON {document.RootElement.ValueKind}, not an array.");
            }

            var containers = new List<DockerContainer>();
            foreach (var container in document.RootElement.EnumerateArray())
            {
                if (container.ValueKind != JsonValueKind.Object)
                {
                    throw new FormatException($"Docker's container list held a {container.ValueKind}, not a container.");
                }

                var id = Text(container, "Id") ?? throw new FormatException("A Docker container had no Id.");

                // Names carries the leading '/' of Docker's old link namespace.
                string? name = null;
                // The engine on a user's socket answers as that user likes: a non-string name must not end the list.
                if (container.TryGetProperty("Names", out var names) &&
                    names.ValueKind == JsonValueKind.Array && names.GetArrayLength() > 0 && names[0].ValueKind == JsonValueKind.String)
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

    private static string? Text(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
