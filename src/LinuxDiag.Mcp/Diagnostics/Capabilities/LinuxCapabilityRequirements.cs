namespace LinuxDiag.Mcp.Diagnostics.Capabilities;

/// <summary>What each of this server's tools needs in order to answer completely.</summary>
/// <remarks>
/// Hand-maintained; GuardTests fails if it disagrees with the tools declared in this assembly and the
/// kit's. A RequiredExecutable is a program name, found by <see cref="PathExecutableResolver"/>.
/// </remarks>
public sealed class LinuxCapabilityRequirements : ICapabilityRequirements
{
    public IReadOnlyDictionary<string, CapabilityRequirement> Requirements => Table;

    private static readonly IReadOnlyDictionary<string, CapabilityRequirement> Table =
        new Dictionary<string, CapabilityRequirement>(StringComparer.Ordinal)
        {
            ["capabilities"] = new("this table, evaluated on this machine", null, null),
            ["put_file"] = new(
                "hash-verified file write over the server's own channel",
                null,
                "can only write where the current account already can"),
            ["get_file"] = new(
                "hash-verified sliced file read over the server's own channel",
                null,
                "can only read what the current account already can"),
        };
}
