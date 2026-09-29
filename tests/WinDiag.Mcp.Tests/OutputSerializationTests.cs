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
        Diag.Mcp.Server.Tests.OutputSerializationGuard.AssertAllPropertiesWritten(model);
    }

    [Fact]
    public void Writes_every_property_of_every_result_model()
    {
        var models = SweptModels();

        // A sweep that matches nothing passes forever.
        Assert.True(models.Count >= 30, $"Expected the result models to be found; got {models.Count}.");

        foreach (var model in models)
        {
            Diag.Mcp.Server.Tests.OutputSerializationGuard.AssertAllPropertiesWritten(model);
        }
    }

    [Fact]
    public void Known_affected_models_are_part_of_the_sweep()
    {
        // Guards the pinned list against a rename or a model dropping out of a tool's return type,
        // either of which would leave the sweep looking healthy while no longer covering what broke.
        var swept = SweptModels();

        foreach (var model in Affected)
        {
            Assert.Contains(model, swept);
        }
    }

    /// <summary>This server's tool results, and those of the kit's tools it serves.</summary>
    private static HashSet<Type> SweptModels() =>
        Diag.Mcp.Server.Tests.OutputSerializationGuard.ResultModels(
            [typeof(ServerBuilder).Assembly, typeof(DiagServerKit).Assembly], "WinDiag.Mcp.Tools", "Diag.Mcp.Server");
}
