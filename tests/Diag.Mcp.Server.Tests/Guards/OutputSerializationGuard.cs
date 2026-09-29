using System.Collections;
using System.Reflection;
using System.Text.Json;

namespace Diag.Mcp.Server.Tests;

/// <summary>Every property of every result model reaches the wire, including the ones that are null.</summary>
/// <remarks>
/// Shared so each server applies it to its own tool results. The full account of the defect this guards
/// -- a required-but-null property dropped by the serializer, and a client rejecting the response against
/// the server's own schema -- is on windiag's OutputSerializationTests.
/// </remarks>
public static class OutputSerializationGuard
{
    /// <summary>
    /// Every record actually reachable from a tool's return type, and so actually serialized.
    /// </summary>
    /// <remarks>
    /// Walked from the <c>[McpServerTool]</c> methods rather than swept by namespace, because "lives
    /// under Diagnostics" is not the same set: <c>ExternalToolPolicy</c>'s request records never reach
    /// the wire and carry members that are not serializable at all. Internal records are excluded for
    /// the same reason -- <c>CapabilityReporter.Requirement</c> has two nullable properties but is a
    /// lookup table, while the type actually serialized (<c>ToolCapability</c>) has none. That is
    /// precisely why <c>capabilities</c> kept working while seven other tools did not.
    /// </remarks>
    public static HashSet<Type> ResultModels(IEnumerable<Assembly> assemblies, params string[] toolNamespacePrefixes)
    {
        var found = new HashSet<Type>();
        var queue = new Queue<Type>();

        // Every assembly the caller names: tool classes shared between servers live in the kit, and a guard
        // over one assembly stops checking a tool's results the moment it moves into another.
        var returnTypes = assemblies
            .SelectMany(assembly => assembly.GetTypes())
            .Where(type => toolNamespacePrefixes.Any(prefix =>
                type.Namespace?.StartsWith(prefix, StringComparison.Ordinal) == true))
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic
                | BindingFlags.Instance | BindingFlags.Static))
            .Where(method => method.GetCustomAttributes()
                .Any(attribute => attribute.GetType().Name == "McpServerToolAttribute"))
            .Select(method => Unwrap(method.ReturnType));

        foreach (var type in returnTypes)
        {
            queue.Enqueue(type);
        }

        while (queue.Count > 0)
        {
            var type = Unwrap(queue.Dequeue());

            if (!type.IsPublic || !IsRecord(type) || PrimaryConstructor(type) is not { } constructor)
            {
                continue;
            }

            if (!found.Add(type))
            {
                continue;
            }

            foreach (var parameter in constructor.GetParameters())
            {
                queue.Enqueue(parameter.ParameterType);
            }
        }

        return found;
    }

    /// <summary>Strips the wrappers that stand between a declared type and the record inside it.</summary>
    private static Type Unwrap(Type type)
    {
        while (true)
        {
            if (Nullable.GetUnderlyingType(type) is { } underlying)
            {
                type = underlying;
                continue;
            }

            if (type.IsArray && type.GetElementType() is { } element)
            {
                type = element;
                continue;
            }

            if (type.IsGenericType)
            {
                var definition = type.GetGenericTypeDefinition();

                if (definition == typeof(Task<>)
                    || definition == typeof(ValueTask<>)
                    || typeof(IEnumerable).IsAssignableFrom(type))
                {
                    type = type.GetGenericArguments()[0];
                    continue;
                }
            }

            return type;
        }
    }

    /// <summary>
    /// Builds an instance with every nullable property null, serializes it as a tool result would be,
    /// and requires a JSON property for each constructor parameter.
    /// </summary>
    public static void AssertAllPropertiesWritten(Type model)
    {
        var constructor = PrimaryConstructor(model);
        Assert.NotNull(constructor);

        var instance = constructor.Invoke([.. constructor.GetParameters().Select(p => Blank(p.ParameterType))]);

        var json = JsonSerializer.Serialize(instance, model, DiagServerKit.ToolJsonOptions);
        using var document = JsonDocument.Parse(json);

        foreach (var parameter in constructor.GetParameters())
        {
            var name = JsonNamingPolicy.CamelCase.ConvertName(parameter.Name!);

            Assert.True(
                document.RootElement.TryGetProperty(name, out _),
                $"{model.Name}.{parameter.Name} was omitted from the serialized result. The tool's output "
                + "schema lists it as required, so a client rejects this response outright. See "
                + "DiagServerKit.ToolJsonOptions.");
        }
    }

    /// <summary>The record's primary constructor -- the one whose parameters became its properties.</summary>
    private static ConstructorInfo? PrimaryConstructor(Type type) =>
        type.GetConstructors()
            .Where(constructor => constructor.GetParameters().Length > 0)
            .OrderByDescending(constructor => constructor.GetParameters().Length)
            .FirstOrDefault(constructor => constructor.GetParameters()
                .All(parameter => type.GetProperty(
                    parameter.Name!,
                    BindingFlags.Public | BindingFlags.Instance) is not null));

    private static bool IsRecord(Type type) =>
        type.GetMethod("<Clone>$", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance) is not null;

    /// <summary>
    /// The emptiest legal value for a parameter: null wherever null is legal, since null is the case
    /// that was being dropped.
    /// </summary>
    private static object? Blank(Type type)
    {
        if (!type.IsValueType || Nullable.GetUnderlyingType(type) is not null)
        {
            // Collections must still be present -- a null list is a different defect, and some models
            // are rendered by code that enumerates them.
            if (type != typeof(string) && typeof(IEnumerable).IsAssignableFrom(type) && type.IsGenericType)
            {
                var element = type.GetGenericArguments()[0];
                return Array.CreateInstance(element, 0);
            }

            return null;
        }

        return Activator.CreateInstance(type);
    }
}
