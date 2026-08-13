namespace WinDiag.Mcp.Diagnostics.External;

/// <summary>Resolves a bundled tool's executable name to a full path.</summary>
public interface IToolLocator
{
    /// <summary>Resolves <paramref name="executableName"/>, or throws <see cref="ToolNotFoundException"/>.</summary>
    string Resolve(string executableName);

    /// <summary>Resolves <paramref name="executableName"/>, returning false when it is not installed.</summary>
    bool TryResolve(string executableName, out string fullPath);
}
