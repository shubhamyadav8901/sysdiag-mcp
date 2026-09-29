using System.Text.Json;
using System.Text.Json.Serialization;
using ModelContextProtocol;

namespace Diag.Mcp.Server;

/// <summary>Shared settings every diagnostics server in this family uses.</summary>
public static class DiagServerKit
{
    /// <summary>
    /// Serializer options for every tool, differing from the SDK's defaults in one respect: a property
    /// whose value is null is written as null rather than omitted.
    /// </summary>
    /// <remarks>
    /// <para>The schema generator marks a constructor parameter required whenever it has no default
    /// value -- nullable or not. (A parameter written <c>= null</c> is marked optional instead, as
    /// <c>LoadedModule.PreferredBase</c> is, which is why that one never broke while <c>Signer</c>
    /// beside it did.) The SDK's default options omit nulls. The two disagree exactly when a required
    /// property is actually null, and the client rejects the response against the schema the server
    /// itself advertised: an unsigned file has no signer, a listening socket has no remote address, an
    /// unlabelled volume has no label. The tool computed the right answer and the caller never saw
    /// it.</para>
    /// <para>Writing nulls satisfies both sides and is set here, once, rather than per property: the
    /// defect is a property of how results are serialized, not of any one model, and forty-odd
    /// attributes are forty-odd chances for the next model to be added without one. It also means
    /// nobody has to audit which parameters happen to carry a default. This is the same fix that
    /// <c>LockHolder</c> carried alone before it was understood to be general.</para>
    /// <para>Note this restores System.Text.Json's own default: <c>Never</c> is the stock value for
    /// <c>DefaultIgnoreCondition</c>, and it is <see cref="McpJsonUtilities.DefaultOptions"/> that opts
    /// into <c>WhenWritingNull</c>. This is a narrower change than "write nulls everywhere" sounds.</para>
    /// <para>Derived from <see cref="McpJsonUtilities.DefaultOptions"/> rather than built fresh, so the
    /// protocol's own converters are kept.</para>
    /// </remarks>
    public static readonly JsonSerializerOptions ToolJsonOptions =
        new(McpJsonUtilities.DefaultOptions) { DefaultIgnoreCondition = JsonIgnoreCondition.Never };
}
