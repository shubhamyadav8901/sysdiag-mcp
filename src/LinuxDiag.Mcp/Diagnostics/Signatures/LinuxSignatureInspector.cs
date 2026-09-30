using LinuxDiag.Mcp.Linux.Native;
using LinuxDiag.Mcp.Linux.Packages;

namespace LinuxDiag.Mcp.Diagnostics.Signatures;

public sealed class LinuxSignatureInspector(IPackageDatabaseSource packages) : ISignatureInspector
{
    /// <summary>Paths one call hashes: each is read in full, so the bound is on the work a single call can start.</summary>
    public const int MaxPaths = 1000;

    public SignatureQueryResult Inspect(IReadOnlyList<string> paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (paths.Count == 0)
        {
            throw new ArgumentException("Provide at least one file path.", nameof(paths));
        }

        if (paths.Count > MaxPaths)
        {
            throw new ArgumentException(
                $"{paths.Count:N0} paths is more than one call hashes; pass at most {MaxPaths} and call again for the rest.", nameof(paths));
        }

        var database = packages.Open();
        var files = new List<FileSignature>();
        var notFound = new List<string>();
        foreach (var path in paths)
        {
            string full;
            try
            {
                full = Path.GetFullPath(path);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                notFound.Add(path);
                continue;
            }

            // Only regular files are opened: reading a FIFO blocks, and a device can be anything.
            var identity = LibC.Supported ? TryIdentify(full) : null;
            if (!File.Exists(full) || identity is null)
            {
                notFound.Add(full);
                continue;
            }

            if (!identity.Value.IsRegular)
            {
                notFound.Add($"{full} (not a regular file)");
                continue;
            }

            // Every link resolved, in the middle of the path too (/usr/lib/jvm/default-java/bin/java): the file
            // hashed is the real one, so it is the real one whose package is asked first.
            string? resolved;
            string sha256, md5;
            try
            {
                var real = LibC.RealPath(full) ?? full;
                resolved = real == full ? null : real;
                (sha256, md5) = FileHashes.Compute(full);
            }
            catch (UnauthorizedAccessException)
            {
                notFound.Add($"{full} (permission denied)");
                continue;
            }
            catch (IOException ex)
            {
                // Replaced by a FIFO or removed since the check above, or an I/O error: this file, not the batch.
                notFound.Add($"{full} ({ex.Message})");
                continue;
            }

            var owner = (resolved is null ? null : database.Owner(resolved)) ?? database.Owner(full);
            var (verdict, detail) = database.Available
                ? DpkgDatabase.Judge(owner, md5)
                : (PackageVerdict.Unknown, "No dpkg database on this machine, so package integrity cannot be checked.");
            var info = new FileInfo(resolved ?? full);
            files.Add(new FileSignature(
                full, verdict, detail, resolved, owner?.Package, owner?.Version, owner?.Conffile ?? false, owner?.DivertedBy,
                info.Length, new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero), sha256));
        }

        var limitation = database.Available
            ? null
            : "This machine has no dpkg database (/var/lib/dpkg), so package ownership and integrity are not checked; sizes and SHA-256 still are.";
        return new SignatureQueryResult(files, notFound, limitation);
    }

    private static FileIdentity? TryIdentify(string path)
    {
        try
        {
            return LibC.Identify(path);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }
}
