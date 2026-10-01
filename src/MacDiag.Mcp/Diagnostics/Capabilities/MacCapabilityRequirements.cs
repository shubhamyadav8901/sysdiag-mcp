namespace MacDiag.Mcp.Diagnostics.Capabilities;

/// <summary>What each of this server's tools needs in order to answer completely.</summary>
/// <remarks>
/// Hand-maintained; GuardTests fails if it disagrees with the tools declared in this assembly and the kit's.
/// A RequiredExecutable is found only in the runner's own directories (SystemExecutableResolver).
/// </remarks>
public sealed class MacCapabilityRequirements : ICapabilityRequirements
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
            ["system_overview"] = new("sw_vers, sysctl, vm_stat, mount, and each volume's size", "sw_vers", null),
            ["run_command"] = new("/bin/zsh -c, /bin/sh -c, /bin/bash -c, or a direct exec", null, null),
        };
}
