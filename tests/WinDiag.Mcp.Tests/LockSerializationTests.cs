using System.Text.Json;
using WinDiag.Mcp.Diagnostics.Locks;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

/// <summary>
/// How a lock holder crosses the wire.
/// </summary>
/// <remarks>
/// <para>who_locks_path advertises an output schema derived from its result type, and the client
/// validates every response against it. A holder that is not a service has no ServiceShortName, so if
/// that property is dropped from the JSON while the schema still demands it, the call fails outright --
/// precisely when the tool has found something, which is the only time anyone calls it.</para>
/// <para>Serialized with <see cref="ServerBuilder.ToolJsonOptions"/>: the guarantee used to come from
/// three <c>JsonIgnore(Never)</c> attributes on the record and now comes from the options every tool is
/// registered with. Asserting against the SDK's <c>DefaultOptions</c>, as this did, tested a
/// configuration the server does not actually use -- which is why the identical defect in every other
/// result model went unnoticed here.</para>
/// </remarks>
public sealed class LockSerializationTests
{
    private static WhoLocksPathResult ResultWithNonServiceHolder() =>
        new(
            Summary: "1 process holds it",
            Path: @"C:\WinDiag\WinDiag.Mcp.exe",
            Holders:
            [
                new LockHolder(
                    ProcessId: 2564,
                    ProcessName: "WinDiag.Mcp",
                    FriendlyName: null,          // Restart Manager reported no display name
                    ServiceShortName: null,      // a plain process, not a service
                    Kind: LockHolderKind.Console,
                    StartedAt: null,
                    StillRunning: true)
            ],
            Exhaustive: false);

    [Fact]
    public void A_non_service_holder_still_carries_every_property_the_schema_requires()
    {
        var json = JsonSerializer.Serialize(ResultWithNonServiceHolder(), ServerBuilder.ToolJsonOptions);

        using var document = JsonDocument.Parse(json);
        var holder = document.RootElement.GetProperty("holders")[0];

        // Present-and-null is what satisfies a schema that lists these as required; omitted is not.
        Assert.True(holder.TryGetProperty("serviceShortName", out var service), $"serviceShortName missing: {json}");
        Assert.Equal(JsonValueKind.Null, service.ValueKind);

        Assert.True(holder.TryGetProperty("friendlyName", out _), $"friendlyName missing: {json}");
        Assert.True(holder.TryGetProperty("startedAt", out _), $"startedAt missing: {json}");
    }
}
