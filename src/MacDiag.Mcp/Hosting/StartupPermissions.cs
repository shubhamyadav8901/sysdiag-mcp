using System.Globalization;
using MacDiag.Mcp.Mac;

namespace MacDiag.Mcp.Hosting;

/// <summary>Refuses a configuration someone other than root could have written.</summary>
/// <remarks>
/// <para>The env file holds the token and the grants of a root daemon. If it, the binary, or any directory
/// above either is writable by another account -- Homebrew hands /usr/local/etc to the installing user on
/// Intel Macs -- that account could plant its own token or enable run_command. So the server refuses to
/// start, before reading a byte, and names every path that is wrong.</para>
/// <para>Each path is checked as spelled and fully resolved. stat without -L reports a link itself, so
/// /etc -> private/etc would otherwise pass as a root-owned 0755 link while /private/etc went unexamined.
/// Ownership comes from stat -f, through the runner: .NET has no owner API, and lstat would mean a native
/// struct whose layout differs by architecture.</para>
/// </remarks>
public static class StartupPermissions
{
    public enum EntryKind
    {
        Directory,
        File,
        Link,
        Other,
    }

    /// <summary>One line of <c>stat -f "%u %Lp %HT %N"</c>.</summary>
    public sealed record StatEntry(string Path, int Uid, int Mode, EntryKind Kind);

    private const int GroupWrite = 0b000_010_000;
    private const int OtherWrite = 0b000_000_010;
    private const int GroupOrOtherAny = 0b000_111_111;

    public static void Require(string envFile, string? executable)
    {
        ArgumentNullException.ThrowIfNull(envFile);

        var env = System.IO.Path.GetFullPath(envFile);
        var exe = executable is null ? null : System.IO.Path.GetFullPath(executable);
        var paths = new[] { env, exe }
            .Where(p => p is not null)
            .SelectMany(p => Chain(p!).Concat(Chain(RealPath(p!))))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var problems = Problems(Inspect(paths), env, exe);
        if (problems.Count > 0)
        {
            throw new ConfigurationException(
                "Refusing to start: another account could have written this configuration. " + string.Join(" ", problems) +
                " Fix the ownership and modes (chown root:wheel, chmod go-w; the env file chmod 600), or reinstall with " +
                "--install-service, which sets them.");
        }
    }

    /// <summary>One stat line per path, from BSD stat run as the system's own program.</summary>
    /// <remarks>
    /// %Mp%Lp, not %Lp alone: %Lp is only the user/group/other digits, and the sticky bit that marks a shared
    /// directory such as /tmp is in %Mp.
    /// </remarks>
    public static IReadOnlyList<StatEntry> Inspect(IReadOnlyList<string> paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        var result = new MacSystemCommand().RunAsync("stat", ["-f", "%u %Mp%Lp %HT %N", "--", .. paths], TimeSpan.FromSeconds(10), CancellationToken.None)
            .GetAwaiter().GetResult();
        if (result.ExitCode != 0)
        {
            throw new ConfigurationException($"Could not check the permissions of {string.Join(", ", paths)}: {result.StandardError.Trim()}");
        }

        return ParseStat(result.StandardOutput);
    }

    /// <summary>The path and every ancestor, root first.</summary>
    public static IReadOnlyList<string> Chain(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        // Split on '/' by hand: these are macOS paths, judged the same way wherever the tests run.
        var chain = new List<string> { path };
        for (var slash = path.LastIndexOf('/'); slash > 0; slash = path.LastIndexOf('/', slash - 1))
        {
            chain.Add(path[..slash]);
        }

        if (path.StartsWith('/') && path != "/")
        {
            chain.Add("/");
        }

        chain.Reverse();
        return chain;
    }

    /// <summary>The path with a link in any component replaced by what it points at.</summary>
    public static string RealPath(string path) => RealPath(path, depth: 0);

    private static string RealPath(string path, int depth)
    {
        // The kernel's own limit on links followed while resolving one path (MAXSYMLINKS).
        if (depth > 32)
        {
            throw new IOException($"Too many levels of symbolic links resolving '{path}'.");
        }

        var current = "/";
        foreach (var part in System.IO.Path.GetFullPath(path).Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            var next = System.IO.Path.Combine(current, part);
            if (new FileInfo(next).LinkTarget is { } target)
            {
                next = RealPath(System.IO.Path.IsPathRooted(target) ? target : System.IO.Path.Combine(current, target), depth + 1);
            }

            current = next;
        }

        return current;
    }

    public static IReadOnlyList<StatEntry> ParseStat(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var entries = new List<StatEntry>();
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.TrimEnd('\r').Split(' ', 3);
            if (parts.Length < 3 ||
                !int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var uid) ||
                !parts[1].All(c => c is >= '0' and <= '7') || parts[1].Length == 0)
            {
                continue;
            }

            var mode = Convert.ToInt32(parts[1], 8);
            var (kind, name) = parts[2] switch
            {
                var rest when rest.StartsWith("Directory ", StringComparison.Ordinal) => (EntryKind.Directory, rest["Directory ".Length..]),
                var rest when rest.StartsWith("Regular File ", StringComparison.Ordinal) => (EntryKind.File, rest["Regular File ".Length..]),
                var rest when rest.StartsWith("Symbolic Link ", StringComparison.Ordinal) => (EntryKind.Link, rest["Symbolic Link ".Length..]),
                var rest => (EntryKind.Other, rest[(rest.IndexOf(" /", StringComparison.Ordinal) + 1)..]),
            };
            entries.Add(new StatEntry(name, uid, mode, kind));
        }

        return entries;
    }

    /// <summary>Everything wrong with the entries, one sentence each, naming the path first.</summary>
    public static IReadOnlyList<string> Problems(IReadOnlyList<StatEntry> entries, string envFile, string? executable)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(envFile);

        static string Octal(int mode) => Convert.ToString(mode, 8).PadLeft(4, '0');

        var problems = new List<string>();
        foreach (var (path, uid, mode, kind) in entries)
        {
            if (uid != 0)
            {
                problems.Add($"{path} is owned by uid {uid}, not root.");
            }

            if (string.Equals(path, envFile, StringComparison.Ordinal))
            {
                if (kind != EntryKind.File)
                {
                    problems.Add($"{path} is {(kind == EntryKind.Link ? "a symbolic link" : "not a regular file")}; the settings file must be a plain file.");
                }
                else if ((mode & GroupOrOtherAny) != 0)
                {
                    problems.Add($"{path} has mode {Octal(mode)}; it must be 0600.");
                }
            }
            else if (kind != EntryKind.Link && (mode & (GroupWrite | OtherWrite)) != 0)
            {
                // A link's own mode means nothing; what it points at is checked as its own entry.
                problems.Add($"{path} is writable by its group or by everyone (mode {Octal(mode)}).");
            }
            else if (string.Equals(path, executable, StringComparison.Ordinal) && kind != EntryKind.File && kind != EntryKind.Link)
            {
                problems.Add($"{path} is not a regular file.");
            }
        }

        return problems;
    }
}
