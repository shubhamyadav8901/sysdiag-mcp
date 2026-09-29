namespace Diag.Mcp.Server.Capabilities;

/// <summary>How usable a tool is on this machine, right now.</summary>
public enum CapabilityStatus
{
    /// <summary>Fully usable.</summary>
    Available,

    /// <summary>Runs, but returns less than the whole truth. The reason says why.</summary>
    Degraded,

    /// <summary>Cannot run at all. The reason says what is missing.</summary>
    Unavailable
}

/// <summary>The state of one tool on this machine.</summary>
public sealed record ToolCapability(string Tool, string Backing, CapabilityStatus Status, string Detail);

/// <summary>Reports which tools can actually do their job here.</summary>
public interface ICapabilityReporter
{
    IReadOnlyList<ToolCapability> Describe();
}

/// <summary>Reports the privilege level the server itself is running with.</summary>
/// <remarks>
/// Several capabilities (exhaustive handle search, kernel tracing, dumping another user's process)
/// silently degrade rather than fail cleanly when unelevated. Tools consult this so they can say
/// "this result may be incomplete because I am not elevated" instead of reporting a partial answer as
/// if it were the whole truth.
/// </remarks>
public interface IPrivilegeProbe
{
    /// <summary>True when this process holds the rights the privileged tools need.</summary>
    bool IsElevated { get; }

    /// <summary>What those rights are called, in a refusal. Defaults to the Windows wording.</summary>
    /// <remarks>
    /// Default members, so every existing probe and test fake keeps compiling and the Windows server's
    /// answers stay word for word what they were; a Linux probe says "root" instead.
    /// </remarks>
    string PrivilegeName => "administrator rights";

    /// <summary>How to get them, in a refusal. Defaults to the Windows wording.</summary>
    string HowToElevate => "Restart the server from an elevated terminal.";
}

/// <summary>What one tool needs in order to answer completely.</summary>
/// <param name="Backing">Implementation, for the reader's benefit.</param>
/// <param name="RequiredExecutable">
/// Helper executable without which this cannot run at all, given as the BASE name -- <c>handle</c>,
/// not <c>handle.exe</c>. Which build is correct depends on the machine being asked, so the server's
/// <see cref="IExecutableResolver"/> decides, exactly as the tool itself will when called.
/// </param>
/// <param name="ElevationNote">
/// Set when running unelevated silently reduces coverage rather than failing. Null when elevation
/// makes no difference.
/// </param>
/// <param name="RequiresElevation">
/// True when the tool cannot run at all unelevated, as opposed to returning less. The distinction
/// matters: <c>Degraded</c> tells the caller to distrust an empty result, <c>Unavailable</c> tells
/// them not to bother calling.
/// </param>
public sealed record CapabilityRequirement(
    string Backing,
    string? RequiredExecutable,
    string? ElevationNote,
    bool RequiresElevation = false);

/// <summary>A server's table of what each of its tools needs, keyed by tool name.</summary>
public interface ICapabilityRequirements
{
    IReadOnlyDictionary<string, CapabilityRequirement> Requirements { get; }
}

/// <summary>Where a helper executable resolved to, or why it could not be used.</summary>
/// <param name="Path">The executable that will run, or null when there is none usable.</param>
/// <param name="Problem">Why not, in words the caller can act on; null when <paramref name="Path"/> is set.</param>
public sealed record ExecutableResolution(string? Path, string? Problem);

/// <summary>Finds the helper executable a tool will run, the way the tool itself will.</summary>
public interface IExecutableResolver
{
    ExecutableResolution Resolve(string baseName);
}
