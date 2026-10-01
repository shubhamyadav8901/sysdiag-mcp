using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Handles;

/// <param name="HandleValue">lsof's FD column: the descriptor number, or txt, cwd, rtd and the like.</param>
/// <param name="Access">"read", "write" or "read-write": how the holder opened it; null when lsof does not say.</param>
public sealed record HandleEntry(
    string ProcessName, int ProcessId, string Type, long? UserId, string HandleValue, string Name, string? Access);

public sealed record HandleSearch(
    string Query, IReadOnlyList<HandleEntry> Entries, bool Elevated, bool Truncated, int TotalMatched,
    IReadOnlyList<string> Limitations, bool IncludedAllObjectTypes, bool ProcessScoped);

public sealed record LoadedModule(string Name, string Path, long? SizeBytes);

public sealed record ModuleListResult(
    int ProcessId, string ProcessName, IReadOnlyList<LoadedModule> Modules, int TotalMatched, bool Truncated,
    IReadOnlyList<string> Limitations);

public interface IHandleInspector
{
    Task<HandleSearch> ForProcessAsync(int processId, bool includeAllObjectTypes, CancellationToken cancellationToken);
}

public interface IModuleInspector
{
    Task<ModuleListResult> ReadAsync(int processId, string? nameFilter, CancellationToken cancellationToken);
}

public sealed class HandleQueryException : Exception, IDiagnosticException
{
    public HandleQueryException(string message)
        : base(message)
    {
    }

    public HandleQueryException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>What kind of object an lsof entry is, in the vocabulary every server's handle tools share.</summary>
public static class HandleKind
{
    public static string Of(LsofFile file)
    {
        ArgumentNullException.ThrowIfNull(file);

        return file.Descriptor switch
        {
            "txt" => "Mapped",
            "cwd" or "rtd" => "Directory",
            _ => file.Type switch
            {
                "REG" => "File",
                "DIR" => "Directory",
                "CHR" or "BLK" => "Device",
                "IPv4" or "IPv6" => "Socket",
                "unix" => "UnixSocket",
                "FIFO" => "Fifo",
                "PIPE" => "Pipe",
                "KQUEUE" => "Kqueue",
                { } other => other,
                null => "Unknown",
            },
        };
    }

    public static bool IsFileReference(string kind) => kind is "File" or "Directory" or "Mapped";

    public static string? Access(string? lsofAccess) => lsofAccess switch
    {
        "r" => "read",
        "w" => "write",
        "u" => "read-write",
        _ => null,
    };
}
