namespace LinuxDiag.Mcp.Diagnostics.Handles;

public sealed record LoadedModule(string Name, string Path, string BaseAddress, long SizeBytes, bool Executable, bool Deleted);

public sealed record ModuleListResult(
    int ProcessId, string ProcessName, IReadOnlyList<LoadedModule> Modules, int TotalMatched, bool Truncated, int DeletedCount);

public sealed class ModuleQueryException : Exception, IDiagnosticException
{
    public ModuleQueryException(string message)
        : base(message)
    {
    }

    public ModuleQueryException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
