using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Handles;

/// <summary>Open files, sockets, pipes and kqueues from lsof.</summary>
public sealed class MacHandleInspector(IExternalCommand commands, IPrivilegeProbe privileges, MacDiagOptions options) : IHandleInspector
{
    /// <summary>Whether a path exists; a seam so tests need no real files.</summary>
    internal Func<string, bool> PathExists { get; init; } = static path => File.Exists(path) || Directory.Exists(path);

    internal IReadOnlyList<string> Firmlinks { get; init; } = PathSpellings.SystemFirmlinks;

    /// <summary>Every open name containing the fragment, under any of its spellings; a full path also by identity.</summary>
    /// <remarks>
    /// The full listing is the answer, because lsof -- &lt;directory&gt; matches the directory's own vnode only, never
    /// what is open beneath it. For a full path, lsof -f -- adds every other name of the same file (a hard link,
    /// a rename after opening), matched by device and inode.
    /// </remarks>
    public async Task<HandleSearch> SearchAsync(string nameFragment, bool includeAllObjectTypes, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nameFragment);

        var rooted = nameFragment.StartsWith('/');
        var wanted = rooted ? PathSpellings.Of(nameFragment.TrimEnd('/') is { Length: > 0 } trimmed ? trimmed : "/", Firmlinks) : [nameFragment];
        var listing = await Mac.Lsof.RunAsync(commands, [], fullListing: true, options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        var entries = listing.SelectMany(Entries)
            .Where(e => includeAllObjectTypes || HandleKind.IsFileReference(e.Type))
            .Where(e => e.Name.Length > 0 && PathSpellings.Of(e.Name, Firmlinks)
                .Any(spelling => wanted.Any(w => spelling.Contains(w, StringComparison.OrdinalIgnoreCase))))
            .ToList();

        if (rooted && PathExists(nameFragment))
        {
            var byIdentity = await Mac.Lsof.RunAsync(commands, ["-f", "--", nameFragment], fullListing: false, options.ExternalToolTimeout, cancellationToken)
                .ConfigureAwait(false);
            entries.AddRange(byIdentity.SelectMany(Entries));
        }

        var unique = entries
            .DistinctBy(e => (e.ProcessId, e.HandleValue))
            .OrderBy(e => e.ProcessName, StringComparer.Ordinal).ThenBy(e => e.ProcessId)
            .ToList();
        return Cap(nameFragment, unique, includeAllObjectTypes, processScoped: false, []);
    }

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
