namespace WinDiag.Mcp.Diagnostics.External;

/// <summary>Resolves a bundled tool's executable name to a full path.</summary>
public interface IToolLocator
{
    /// <summary>Resolves <paramref name="executableName"/>, or throws <see cref="ToolNotFoundException"/>.</summary>
    string Resolve(string executableName);

    /// <summary>Resolves <paramref name="executableName"/>, returning false when it is not installed.</summary>
    /// <exception cref="UntrustedToolException">
    /// It is installed, but in a place this server refuses to run it from unsigned: "not installed" would
    /// be untrue.
    /// </exception>
    bool TryResolve(string executableName, out string fullPath);
}
