namespace Diag.Mcp.Server.Tests;

/// <summary>
/// The rule every server must keep for its two most dangerous tools: each is registered only with its
/// own grant, and a read-only server gets neither -- nor put_file.
/// </summary>
/// <remarks>
/// Each server registers update_self and run_command itself, because their descriptions are
/// compile-time text naming that platform's shells and file names. So the rule is written once here and
/// every server's suite runs it against its own registration, rather than each copying the check.
/// </remarks>
public static class GatedToolGuard
{
    /// <param name="toolNames">The server's tool names for (readOnly, allowSelfUpdate, allowCommands).</param>
    public static void AssertGatedToolsFollowTheirGrants(Func<bool, bool, bool, IReadOnlyCollection<string>> toolNames)
    {
        ArgumentNullException.ThrowIfNull(toolNames);

        var ungranted = toolNames(false, false, false);
        Assert.DoesNotContain("update_self", ungranted);
        Assert.DoesNotContain("run_command", ungranted);
        Assert.Contains("put_file", ungranted);
        Assert.Contains("process_control", ungranted);

        var update = toolNames(false, true, false);
        Assert.Contains("update_self", update);
        Assert.DoesNotContain("run_command", update);

        var commands = toolNames(false, false, true);
        Assert.Contains("run_command", commands);
        Assert.DoesNotContain("update_self", commands);

        var readOnly = toolNames(true, true, true);
        Assert.DoesNotContain("update_self", readOnly);
        Assert.DoesNotContain("run_command", readOnly);
        Assert.DoesNotContain("put_file", readOnly);
        Assert.DoesNotContain("process_control", readOnly);
        Assert.Contains("get_file", readOnly);
    }
}
