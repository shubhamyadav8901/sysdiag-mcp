using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Handles;

/// <summary>Open files, sockets, pipes and kqueues from lsof.</summary>
public sealed class MacHandleInspector(IExternalCommand commands, IPrivilegeProbe privileges, MacDiagOptions options) : IHandleInspector
{
    public async Task<HandleSearch> ForProcessAsync(int processId, bool includeAllObjectTypes, CancellationToken cancellationToken)
    {
        var process = await ProcessFiles.ReadAsync(commands, options, processId, cancellationToken).ConfigureAwait(false);
        var entries = Entries(process).Where(e => includeAllObjectTypes || HandleKind.IsFileReference(e.Type)).ToList();
        return Cap($"PID {processId}", entries, includeAllObjectTypes, processScoped: true, []);
    }

    internal static IEnumerable<HandleEntry> Entries(LsofProcess process) =>
        process.Files.Select(f => new HandleEntry(
            process.Command, process.ProcessId, HandleKind.Of(f), process.UserId, f.Descriptor, f.Name ?? string.Empty,
            HandleKind.Access(f.Access)));

    internal HandleSearch Cap(string query, IReadOnlyList<HandleEntry> entries, bool includeAll, bool processScoped, IReadOnlyList<string> limitations)
    {
        var kept = entries.Take(options.MaxResults).ToList();
        return new HandleSearch(query, kept, privileges.IsElevated, entries.Count > kept.Count, entries.Count, limitations, includeAll, processScoped);
    }
}

/// <summary>A process's mapped executable and libraries: lsof's txt entries.</summary>
public sealed class MacModuleInspector(IExternalCommand commands, IPrivilegeProbe privileges, MacDiagOptions options) : IModuleInspector
{
    /// <summary>Always true on macOS, and the reason a module list looks short.</summary>
    internal const string SharedCacheNote =
        "System libraries live in the dyld shared cache and are not listed one by one; the executable, dyld and " +
        "any library outside the cache are.";

    public async Task<ModuleListResult> ReadAsync(int processId, string? nameFilter, CancellationToken cancellationToken)
    {
        var process = await ProcessFiles.ReadAsync(commands, options, processId, cancellationToken).ConfigureAwait(false);
        var modules = process.Files
            .Where(f => f.Descriptor == "txt" && f.Name is not null)
            .Where(f => string.IsNullOrWhiteSpace(nameFilter) || f.Name!.Contains(nameFilter, StringComparison.OrdinalIgnoreCase))
            .Select(f => new LoadedModule(f.Name![(f.Name!.LastIndexOf('/') + 1)..], f.Name!, f.Size))
            .ToList();
        var kept = modules.Take(options.MaxResults).ToList();
        List<string> limitations = [SharedCacheNote];
        if (!privileges.IsElevated)
        {
            limitations.Add("The server is not root, so another user's process may show fewer files than it has open.");
        }

        return new ModuleListResult(processId, process.Command, kept, modules.Count, modules.Count > kept.Count, limitations);
    }
}
