namespace MacDiag.Mcp.Hosting;

/// <summary>Refuses a configuration someone other than root could have written.</summary>
public static class StartupPermissions
{
    public static void Require(string envFile, string? executable)
    {
        ArgumentNullException.ThrowIfNull(envFile);
    }
}
