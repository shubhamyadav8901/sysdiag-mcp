using System.Security.Cryptography;
using LinuxDiag.Mcp.Linux.Native;

namespace LinuxDiag.Mcp.Linux.Packages;

/// <param name="Package">The owner, qualified as dpkg names its files ("libc6:amd64").</param>
/// <param name="ExpectedMd5">From the package's md5sums, or its conffile record; null when it records none.</param>
/// <param name="Conffile">A configuration file, expected to change locally.</param>
/// <param name="DivertedBy">The package whose diversion put this file where it is.</param>
public sealed record PackageFile(string Package, string? Version, string? ExpectedMd5, bool Conffile, string? DivertedBy);

public enum PackageVerdict
{
    Valid,
    Modified,
    ConfigurationChanged,
    Unpackaged,
    Unknown,
}

public interface IPackageDatabase
{
    bool Available { get; }

    PackageFile? Owner(string path);
}

/// <summary>Opens the database fresh: an index cached for the life of the process goes stale at the next apt run.</summary>
public interface IPackageDatabaseSource
{
    IPackageDatabase Open();
}

public sealed class DpkgDatabaseSource : IPackageDatabaseSource
{
    public IPackageDatabase Open() => new DpkgDatabase();
}

public sealed record PackageStatus(string? Version, IReadOnlyDictionary<string, string> Conffiles);

/// <summary>dpkg's own records under /var/lib/dpkg, read directly.</summary>
/// <remarks>
/// Not <c>dpkg -S</c> and <c>dpkg --verify</c>: -S misses usr-merge aliases and --verify goes a package at a
/// time. The files are dpkg's internals, so every read is defensive -- a line a concurrent apt run left
/// half-written is skipped, never a failure. What this proves is that a file matches the database, which
/// root can rewrite: integrity, not provenance.
/// </remarks>
public sealed class DpkgDatabase : IPackageDatabase
{
    public const string DefaultRoot = "/var/lib/dpkg";

    private static readonly (string Short, string Long)[] UsrMerge =
        [("/bin", "/usr/bin"), ("/sbin", "/usr/sbin"), ("/lib", "/usr/lib"), ("/lib64", "/usr/lib64"), ("/lib32", "/usr/lib32")];

    private readonly string _root;
    private readonly Lazy<Index> _index;
    private readonly Dictionary<string, IReadOnlyDictionary<string, string>> _md5 = new(StringComparer.Ordinal);

    public DpkgDatabase()
        : this(DefaultRoot)
    {
    }

    internal DpkgDatabase(string root)
    {
        _root = root;
        _index = new Lazy<Index>(Load);
    }

    public bool Available => Directory.Exists(Path.Combine(_root, "info"));

    public PackageFile? Owner(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        var index = _index.Value;

        // A diversion moves a package's file aside: the file now at 'to' is the original package's 'from',
        // and the path 'from' now holds the diverting package's own file.
        if (index.DivertedTo.TryGetValue(path, out var moved))
        {
            return Find(moved.From, except: moved.Package, divertedBy: moved.Package);
        }

        return index.DivertedFrom.TryGetValue(path, out var diverting)
            ? Find(path, only: diverting.Package, divertedBy: diverting.Package)
            : Find(path, null, null);
    }

    public static (PackageVerdict Verdict, string Detail) Judge(PackageFile? owner, string actualMd5)
    {
        if (owner is null)
        {
            return (PackageVerdict.Unpackaged, "No installed package owns this file.");
        }

        var package = owner.Version is null ? owner.Package : $"{owner.Package} {owner.Version}";
        if (owner.ExpectedMd5 is null)
        {
            return (PackageVerdict.Unknown, $"Owned by {package}, which records no checksum for it.");
        }

        var matches = string.Equals(owner.ExpectedMd5, actualMd5, StringComparison.OrdinalIgnoreCase);
        if (owner.Conffile)
        {
            return matches
                ? (PackageVerdict.Valid, $"Configuration file of {package}, as the package shipped it.")
                : (PackageVerdict.ConfigurationChanged, $"Configuration file of {package}, changed locally - normal for configuration, worth reading if unexpected.");
        }

        return matches
            ? (PackageVerdict.Valid, $"Content matches the dpkg database for {package}.")
            : (PackageVerdict.Modified, $"Does NOT match the dpkg database for {package}: the file changed after the package installed it.");
    }

    internal static Dictionary<string, string> ParseMd5Sums(string text)
    {
        var sums = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var space = line.IndexOf(' ', StringComparison.Ordinal);
            if (space == 32 && line.Length > 34)
            {
                sums.TryAdd("/" + line[34..].TrimEnd('\r'), line[..32]);
            }
        }

        return sums;
    }

    internal static List<(string From, string To, string Package)> ParseDiversions(string text)
    {
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var diversions = new List<(string, string, string)>();
        for (var i = 0; i + 2 < lines.Length; i += 3)
        {
            diversions.Add((lines[i], lines[i + 1], lines[i + 2]));
        }

        return diversions;
    }

    /// <summary>Each stanza's Version and Conffiles, keyed by package name and, when it has one, name:architecture.</summary>
    internal static Dictionary<string, PackageStatus> ParseStatus(string text)
    {
        var status = new Dictionary<string, PackageStatus>(StringComparer.Ordinal);
        foreach (var stanza in text.Split("\n\n", StringSplitOptions.RemoveEmptyEntries))
        {
            string? package = null, architecture = null, version = null;
            var conffiles = new Dictionary<string, string>(StringComparer.Ordinal);
            var inConffiles = false;
            foreach (var line in stanza.Split('\n'))
            {
                if (line.StartsWith(' ') && inConffiles)
                {
                    var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && parts[1].Length == 32)
                    {
                        conffiles[parts[0]] = parts[1];
                    }

                    continue;
                }

                inConffiles = line.StartsWith("Conffiles:", StringComparison.Ordinal);
                if (line.StartsWith("Package: ", StringComparison.Ordinal)) package = line[9..].Trim();
                else if (line.StartsWith("Architecture: ", StringComparison.Ordinal)) architecture = line[14..].Trim();
                else if (line.StartsWith("Version: ", StringComparison.Ordinal)) version = line[9..].Trim();
            }

            if (package is not null)
            {
                var record = new PackageStatus(version, conffiles);
                status.TryAdd(package, record);
                if (architecture is not null and not "all")
                {
                    status.TryAdd($"{package}:{architecture}", record);
                }
            }
        }

        return status;
    }

    private PackageFile? Find(string listed, string? except = null, string? only = null, string? divertedBy = null)
    {
        var index = _index.Value;
        foreach (var candidate in Aliases(listed))
        {
            if (!index.Owners.TryGetValue(candidate, out var packages))
            {
                continue;
            }

            var package = packages.FirstOrDefault(p =>
                (except is null || BaseName(p) != except) && (only is null || BaseName(p) == only));
            if (package is null)
            {
                continue;
            }

            var status = index.Status.GetValueOrDefault(package) ?? index.Status.GetValueOrDefault(BaseName(package));
            var conffile = status?.Conffiles.GetValueOrDefault(candidate);
            var md5 = conffile ?? Md5Sums(package).GetValueOrDefault(candidate);
            return new PackageFile(package, status?.Version, md5, conffile is not null, divertedBy);
        }

        return null;
    }

    /// <summary>The path and its usr-merge twin: a package may list /bin/x for the file at /usr/bin/x, or the reverse.</summary>
    private static IEnumerable<string> Aliases(string path)
    {
        yield return path;
        foreach (var (shortForm, longForm) in UsrMerge)
        {
            if (path.StartsWith(shortForm + "/", StringComparison.Ordinal))
            {
                yield return longForm + path[shortForm.Length..];
            }
            else if (path.StartsWith(longForm + "/", StringComparison.Ordinal))
            {
                yield return shortForm + path[longForm.Length..];
            }
        }
    }

    private static string BaseName(string package) => package.Split(':')[0];

    private IReadOnlyDictionary<string, string> Md5Sums(string package)
    {
        if (!_md5.TryGetValue(package, out var sums))
        {
            _md5[package] = sums = ParseMd5Sums(ReadOrEmpty(Path.Combine(_root, "info", package + ".md5sums")));
        }

        return sums;
    }

    private Index Load()
    {
        var owners = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var info = Path.Combine(_root, "info");
        if (Directory.Exists(info))
        {
            foreach (var list in Directory.EnumerateFiles(info, "*.list"))
            {
                var package = Path.GetFileNameWithoutExtension(list);
                foreach (var line in ReadOrEmpty(list).Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (line.StartsWith('/') && line != "/.")
                    {
                        if (!owners.TryGetValue(line, out var packages))
                        {
                            owners[line] = packages = [];
                        }

                        packages.Add(package);
                    }
                }
            }
        }

        var diversions = ParseDiversions(ReadOrEmpty(Path.Combine(_root, "diversions")));
        return new Index(
            owners,
            ParseStatus(ReadOrEmpty(Path.Combine(_root, "status"))),
            ByEveryAlias(diversions, d => d.To),
            ByEveryAlias(diversions, d => d.From));
    }

    /// <summary>Diversions keyed under every usr-merge spelling of the path: dpkg records one, callers ask by either.</summary>
    private static Dictionary<string, (string From, string To, string Package)> ByEveryAlias(
        List<(string From, string To, string Package)> diversions, Func<(string From, string To, string Package), string> key)
    {
        return diversions
            .SelectMany(d => Aliases(key(d)).Select(alias => (Alias: alias, Diversion: d)))
            .GroupBy(x => x.Alias, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().Diversion, StringComparer.Ordinal);
    }

    private static string ReadOrEmpty(string path)
    {
        try
        {
            return File.Exists(path) ? File.ReadAllText(path) : string.Empty;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return string.Empty;
        }
    }

    private sealed record Index(
        Dictionary<string, List<string>> Owners,
        Dictionary<string, PackageStatus> Status,
        Dictionary<string, (string From, string To, string Package)> DivertedTo,
        Dictionary<string, (string From, string To, string Package)> DivertedFrom);
}

public static class FileHashes
{
    /// <summary>SHA-256 for the caller and MD5 for dpkg's checksums, in one read.</summary>
    public static (string Sha256, string Md5) Compute(string path)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        // Never a FIFO or device: a path swapped for one between a caller's check and this read must not hang it.
        using var stream = new FileStream(LibC.OpenRegularFile(path), FileAccess.Read);
        var buffer = new byte[81920];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            sha.AppendData(buffer, 0, read);
            md5.AppendData(buffer, 0, read);
        }

        return (Convert.ToHexString(sha.GetHashAndReset()), Convert.ToHexString(md5.GetHashAndReset()).ToLowerInvariant());
    }
}
