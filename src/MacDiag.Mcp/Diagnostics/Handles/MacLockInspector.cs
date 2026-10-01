using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Processes;

namespace MacDiag.Mcp.Diagnostics.Handles;

/// <summary>Who holds a path open, from lsof -f -- &lt;path&gt;, which matches the file itself by device and inode.</summary>
/// <remarks>
/// -f makes lsof treat the path as one file even when it is a mount point; without it, "/" would list every open file
/// on the volume.
/// </remarks>
public sealed class MacLockInspector(IExternalCommand commands, IProcessTable processes, IPrivilegeProbe privileges, MacDiagOptions options)
    : ILockInspector
{
    internal const string LockStateNote =
        "macOS's lsof does not report lock state: these are the processes that have the path open; which of them " +
        "holds a lock is not visible.";

    internal Func<string, bool> PathExists { get; init; } = static path => File.Exists(path) || Directory.Exists(path);

    internal IReadOnlyList<string> Firmlinks { get; init; } = PathSpellings.SystemFirmlinks;

    public async Task<LockQuery> QueryAsync(string fullPath, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fullPath);

        List<string> limitations = [LockStateNote];
        if (!privileges.IsElevated)
        {
            limitations.Add("The server is not root, so processes owned by other users were not searched.");
        }

        if (!PathExists(fullPath))
        {
            return new LockQuery(fullPath, false, [], privileges.IsElevated, limitations, 0, false);
        }

        var listed = await Mac.Lsof.RunAsync(commands, ["-f", "--", fullPath], fullListing: false, options.ExternalToolTimeout, cancellationToken)
            .ConfigureAwait(false);

        // lsof lists every library a process maps as txt, the executable among them; only ps says which one it runs.
        var executables = listed.Any(p => p.Files.Any(f => f.Descriptor == "txt"))
            ? (await processes.ReadAsync(cancellationToken).ConfigureAwait(false)).Processes
                .Where(p => p.ExecutablePath is not null)
                .ToDictionary(p => p.ProcessId, p => p.ExecutablePath!)
            : [];
        var spellings = PathSpellings.Of(fullPath, Firmlinks);

        var holders = listed
            .SelectMany(p => p.Files.Select(f => new LockHolder(p.ProcessId, p.Command, KindOf(p.ProcessId, f.Descriptor), HandleKind.Access(f.Access))))
            .OrderBy(h => h.ProcessId)
            .ToList();
        var kept = holders.Take(options.MaxResults).ToList();
        return new LockQuery(fullPath, true, kept, privileges.IsElevated, limitations, holders.Count, holders.Count > kept.Count);

        LockHolderKind KindOf(int processId, string descriptor) => descriptor switch
        {
            "txt" => executables.TryGetValue(processId, out var executable) &&
                     PathSpellings.Of(executable, Firmlinks).Any(e => spellings.Contains(e, StringComparer.Ordinal))
                ? LockHolderKind.Executing
                : LockHolderKind.Mapped,
            "cwd" => LockHolderKind.WorkingDirectory,
            "rtd" => LockHolderKind.RootDirectory,
            "mem" => LockHolderKind.Mapped,
            _ when descriptor.Length > 0 && char.IsAsciiDigit(descriptor[0]) => LockHolderKind.Open,
            _ => LockHolderKind.Other,
        };
    }
}
