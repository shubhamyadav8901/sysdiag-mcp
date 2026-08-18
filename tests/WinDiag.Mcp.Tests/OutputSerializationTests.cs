using System.Collections;
using System.Reflection;
using System.Text.Json;
using WinDiag.Mcp.Diagnostics.Access;
using WinDiag.Mcp.Diagnostics.Autostart;
using WinDiag.Mcp.Diagnostics.Locks;
using WinDiag.Mcp.Diagnostics.Modules;
using WinDiag.Mcp.Diagnostics.Network;
using WinDiag.Mcp.Diagnostics.Processes;
using WinDiag.Mcp.Diagnostics.Signatures;
using WinDiag.Mcp.Diagnostics.SystemInfo;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// Every property of a result model reaches the wire, including the ones that are null.
/// </summary>
/// <remarks>
/// <para>The output schema generated for a tool marks every constructor parameter without a default
/// value as required -- nullable or not. If the serializer omits nulls, a response is rejected by the
/// client against the server's own advertised schema, and only when such a property happens to be null,
/// which is why it survived a full green suite. Seven tools were unusable from a real MCP client this
/// way: an unsigned file has no signer, a listening socket no remote address, an unlabelled volume no
/// label. (A parameter written <c>= null</c> is marked optional and was never affected, which is why
/// <c>LoadedModule.PreferredBase</c> survived while <c>Signer</c> beside it did not. This test asserts
/// presence for every parameter regardless, which is a superset of the required ones and so cannot
/// pass while the real invariant is broken.)</para>
/// <para>This asserts the serialization half of that contract, which is the half that was wrong. It is
/// not a full schema-conformance check -- it does not invoke tools or validate against the generated
/// schema -- so it holds only as long as schema generation continues to mark these properties required.
/// That direction was verified by hand against a live server; this guards the direction that broke.</para>
/// </remarks>
public sealed class OutputSerializationTests
{
    /// <summary>
    /// Result models whose nullable properties are known to go null in the field.
    /// </summary>
    /// <remarks>
    /// Pinned by name so the reflection sweep below cannot quietly cover nothing. Each of these
    /// produced a client-side rejection on a real target before the fix.
    /// </remarks>
    private static readonly Type[] Affected =
    [
        typeof(LogicalDisk),
        typeof(FileSignature),
        typeof(NetworkEndpoint),
        typeof(ProcessInfo),
        typeof(LoadedModule),
        typeof(AutostartEntry),
        typeof(AccessReport),
        typeof(LockHolder)
    ];

    public static TheoryData<Type> KnownAffectedModels() => [.. Affected];

    [Theory]
    [MemberData(nameof(KnownAffectedModels))]
    public void Writes_every_property_of_a_known_affected_model(Type model)
    {
        AssertAllPropertiesWritten(model);
    }

    [Fact]
    public void Writes_every_property_of_every_result_model()
    {
        var models = ResultModels();

        // A sweep that matches nothing passes forever.
        Assert.True(models.Count >= 30, $"Expected the result models to be found; got {models.Count}.");

        foreach (var model in models)
        {
            AssertAllPropertiesWritten(model);
        }
    }

    [Fact]
    public void Known_affected_models_are_part_of_the_sweep()
    {
        // Guards the pinned list against a rename or a model dropping out of a tool's return type,
        // either of which would leave the sweep looking healthy while no longer covering what broke.
        var swept = ResultModels();

        foreach (var model in Affected)
        {
            Assert.Contains(model, swept);
        }
    }

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
    private static HashSet<Type> ResultModels()
    {
        var found = new HashSet<Type>();
        var queue = new Queue<Type>();

        var returnTypes = typeof(ServerBuilder).Assembly
            .GetTypes()
            .Where(type => type.Namespace?.StartsWith("WinDiag.Mcp.Tools", StringComparison.Ordinal) == true)
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
    private static void AssertAllPropertiesWritten(Type model)
    {
        var constructor = PrimaryConstructor(model);
        Assert.NotNull(constructor);

        var instance = constructor.Invoke([.. constructor.GetParameters().Select(p => Blank(p.ParameterType))]);

        var json = JsonSerializer.Serialize(instance, model, ServerBuilder.ToolJsonOptions);
        using var document = JsonDocument.Parse(json);

        foreach (var parameter in constructor.GetParameters())
        {
            var name = JsonNamingPolicy.CamelCase.ConvertName(parameter.Name!);

            Assert.True(
                document.RootElement.TryGetProperty(name, out _),
                $"{model.Name}.{parameter.Name} was omitted from the serialized result. The tool's output "
                + "schema lists it as required, so a client rejects this response outright. See "
                + "ServerBuilder.ToolJsonOptions.");
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
