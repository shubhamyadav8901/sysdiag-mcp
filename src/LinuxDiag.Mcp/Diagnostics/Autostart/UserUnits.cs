using LinuxDiag.Mcp.Linux.Native;
using LinuxDiag.Mcp.Linux.Parsers;

namespace LinuxDiag.Mcp.Diagnostics.Autostart;

/// <summary>The unit file and drop-ins systemd would load for a unit, in the order it applies them.</summary>
internal sealed record UnitFiles(string? Fragment, IReadOnlyList<string> DropIns);

/// <summary>Users' systemd units, found and resolved from files the way a user's manager does.</summary>
/// <remarks>
/// Files rather than <c>systemctl --user -M user@ show</c>: a user's manager runs only while they are logged in
/// (or lingering), and an audit that saw only logged-in users would miss exactly the units waiting for a login.
/// A user's XDG_* variables live in their session, which the server cannot see, so systemd's defaults are used.
/// </remarks>
/// <param name="read">A configuration file's text, or empty; the server's own reader opens only regular files.</param>
/// <param name="realPath">Where a path leads, links resolved; null when it leads nowhere.</param>
/// <param name="root">Prefixed to every system directory; empty except under test.</param>
internal sealed class UserUnits(Func<string, string> read, Func<string, string?> realPath, string root = "")
{
    private static readonly Dictionary<string, string> TriggerSections = new(StringComparer.Ordinal)
    {
        [".timer"] = "Timer", [".socket"] = "Socket", [".path"] = "Path",
    };

    /// <summary>The server's own readers: <see cref="LinuxAutostartInspector.ReadConfiguration"/> and realpath(3).</summary>
    internal static UserUnits Reading(string root = "") => new(LinuxAutostartInspector.ReadConfiguration, SafeRealPath, root);

    /// <summary>Every enabled user unit: once for every user when enabled globally, and per user where theirs differs.</summary>
    internal IEnumerable<AutostartEntry> Audit(IReadOnlyList<PasswdEntry> accounts, Func<string, bool> lingering, List<string> limitations)
    {
        var global = SearchPath(null, null);
        List<(string Name, string Link)> globalUnits;
        try
        {
            globalUnits = Enabled(global);
        }
        catch (UnauthorizedAccessException ex)
        {
            // One unreadable directory must not cost the users' own units; it is named instead.
            limitations.Add($"Units enabled for every user could not all be read ({ex.Message}); run the server as root.");
            globalUnits = [];
        }

        var globalEntries = new Dictionary<string, AutostartEntry>(StringComparer.Ordinal);
        foreach (var (name, link) in globalUnits)
        {
            var entry = Entry(name, link, global, null, "starts at every user's login");
            globalEntries[name] = entry;
            yield return entry;
        }

        var unreadable = 0;
        foreach (var account in accounts.Where(a => a.Home.Length > 1))
        {
            // Directory.Exists says false for a directory behind one the server cannot search, so an unreadable
            // home is looked for explicitly rather than read as "no user units".
            var personal = PersonalDirectories(account.Home);
            bool any;
            try
            {
                any = personal.Any(Directory.Exists);
                if (!any && Directory.Exists(account.Home))
                {
                    _ = Directory.EnumerateFileSystemEntries(account.Home).Any();
                }
            }
            catch (UnauthorizedAccessException)
            {
                unreadable++;
                continue;
            }

            if (!any)
            {
                continue;
            }

            var path = SearchPath(account.Home, account.UserId);
            var when = lingering(account.Name) ? "starts at boot (lingering)" : "starts at the user's login";
            IReadOnlyList<(string Name, string Link)> own;
            try
            {
                own = Enabled(personal);
            }
            catch (UnauthorizedAccessException)
            {
                unreadable++;
                continue;
            }

            foreach (var (name, link) in own)
            {
                yield return Entry(name, link, path, account.Name, when);
            }

            // A user needs no enable to change a unit enabled for everyone: their own unit file or drop-in -- even a
            // type-wide one such as ~/.config/systemd/user/service.d/x.conf -- replaces what it runs at their login.
            // The whole entry is resolved for the user and its files compared, not just the enabled unit's: for a
            // socket or timer the files that decide the program are the started service's, and pipewire.socket,
            // enabled for everyone, would otherwise hide a user's pipewire.service.d override behind /usr/bin/pipewire.
            foreach (var (name, link) in globalUnits.Where(g => own.All(o => o.Name != g.Name)))
            {
                var mine = Entry(name, link, path, account.Name, when + " - this user's own files change what it runs");
                var everyone = globalEntries[name];
                if (mine.Location != everyone.Location || !mine.DropIns.SequenceEqual(everyone.DropIns))
                {
                    yield return mine;
                }
            }
        }

        if (unreadable > 0)
        {
            limitations.Add($"{unreadable} home directories could not be read, so those users' units are missing; run the server as root.");
        }
    }

    /// <summary>systemd's user unit search path, highest priority first; without a user, the part every user shares.</summary>
    /// <remarks>
    /// The order of path-lookup.c's user_dirs(), with XDG defaults. Order decides which unit file is loaded and
    /// which of two same-named drop-ins applies, and ~/.config sits above /usr/lib: a user shadows a packaged unit.
    /// </remarks>
    internal IReadOnlyList<string> SearchPath(string? home, long? uid)
    {
        string? Home(string relative) => home is null ? null : Path.Combine(home, relative);
        string? Runtime(string relative) => uid is null ? null : $"{root}/run/user/{uid}/systemd/{relative}";
        string?[] directories =
        [
            Home(".config/systemd/user.control"), Runtime("user.control"), Runtime("transient"), Runtime("generator.early"),
            Home(".config/systemd/user"), root + "/etc/xdg/systemd/user", root + "/etc/systemd/user",
            Runtime("user"), root + "/run/systemd/user", Runtime("generator"),
            Home(".local/share/systemd/user"), root + "/usr/local/share/systemd/user", root + "/usr/share/systemd/user",
            root + "/usr/local/lib/systemd/user", root + "/usr/lib/systemd/user", Runtime("generator.late"),
        ];
        return directories.OfType<string>().Distinct(StringComparer.Ordinal).ToList();
    }

    /// <summary>The directories a user writes and that survive a reboot: where their own enables and overrides live.</summary>
    /// <remarks>
    /// /run/user/UID is searched when resolving a unit, as systemd does, but not for enables or overrides of its own:
    /// it is tmpfs, so nothing put there starts again after a reboot.
    /// </remarks>
    private static string[] PersonalDirectories(string home) =>
    [
        Path.Combine(home, ".config/systemd/user.control"), Path.Combine(home, ".config/systemd/user"),
        Path.Combine(home, ".local/share/systemd/user"),
    ];

    /// <summary>The units enabled through these directories' *.wants and *.requires links, by name, first link kept.</summary>
    /// <remarks>systemd enables by the link's name and loads that name from the search path; the target is only a fallback.</remarks>
    private static List<(string Name, string Link)> Enabled(IEnumerable<string> directories)
    {
        var units = new List<(string Name, string Link)>();
        foreach (var directory in directories.Where(Directory.Exists))
        {
            foreach (var link in Directory.EnumerateDirectories(directory, "*.wants")
                         .Concat(Directory.EnumerateDirectories(directory, "*.requires"))
                         .Order(StringComparer.Ordinal)
                         .SelectMany(d => Directory.EnumerateFileSystemEntries(d).Order(StringComparer.Ordinal)))
            {
                // systemd ignores a name that is not a unit's, and so does the audit: it has no type to resolve.
                var name = Path.GetFileName(link);
                if (Path.GetExtension(name).Length > 1 && units.All(u => u.Name != name))
                {
                    units.Add((name, link));
                }
            }
        }

        return units;
    }

    private AutostartEntry Entry(string name, string link, IReadOnlyList<string> path, string? user, string description)
    {
        var files = Resolve(name, path);

        // A link loop or a dangling link is the user's to make; it names the entry rather than failing the audit.
        var location = files.Fragment is { } fragment ? RealOr(fragment) : RealOr(link);
        var texts = Texts(location, files.DropIns);
        var dropIns = files.DropIns.ToList();

        // A timer, socket or path runs another unit; what runs is that unit's ExecStart, and its own files decide it.
        var runs = TriggerSections.TryGetValue(Path.GetExtension(name), out var section) ? Triggered(name, section, texts) : null;
        if (runs is not null)
        {
            var runner = Resolve(runs, path);
            var runnerLocation = runner.Fragment is { } runnerFragment ? RealOr(runnerFragment) : null;
            texts = Texts(runnerLocation, runner.DropIns);
            dropIns.AddRange(runner.DropIns.Prepend(runnerLocation ?? string.Empty).Where(f => f.Length > 0));
            description += $" (runs {runs})";
        }

        var execStart = UnitFile.Values(texts, "Service", "ExecStart").FirstOrDefault()?.TrimStart('-', '@', '+', '!', ':');
        var (program, script) = execStart is null ? (null, null) : LaunchCommand.Split(execStart);
        return new AutostartEntry(
            "userunits", location, name, true, user ?? "(every user)", description, program, execStart, script,
            dropIns, null, null, [], program is not null && program.StartsWith('/') && !File.Exists(program));
    }

    private List<string> Texts(string? fragment, IEnumerable<string> dropIns) =>
        (fragment is null ? dropIns : dropIns.Prepend(fragment)).Select(read).ToList();

    /// <summary>The unit a timer, socket or path starts: Unit=, or by default the service of the same name.</summary>
    /// <remarks>A socket with Accept=yes starts an instance per connection, of the template of its own name.</remarks>
    private static string Triggered(string name, string section, List<string> texts)
    {
        if (UnitFile.Last(texts, section, "Unit") is { } unit)
        {
            return unit;
        }

        var stem = Path.GetFileNameWithoutExtension(name);
        var accept = section == "Socket" && UnitFile.Last(texts, section, "Accept") is "yes" or "true" or "on" or "1";
        return stem + (accept ? "@.service" : ".service");
    }

    /// <summary>The unit file loaded for a name, and the drop-ins applied to it, in the order they apply.</summary>
    internal UnitFiles Resolve(string name, IReadOnlyList<string> path)
    {
        // The first directory holding the name wins; an instance falls back to its template's file.
        // A link that leads nowhere is skipped, as systemd skips it, so a lower directory's file still loads.
        var candidates = new[] { name, Template(name) }.OfType<string>();
        var fragment = candidates
            .SelectMany(c => path.Select(d => Path.Combine(d, c)))
            .FirstOrDefault(File.Exists);

        // A unit file linked under another name is an alias, and the drop-ins of every name apply: the name the
        // fragment's link leads to, and every link anywhere in the search path that leads to the same file.
        var names = new List<string> { name };
        if (fragment is not null)
        {
            var real = RealOr(fragment);
            if (Path.GetFileName(real) is var file && file != name && file != Template(name) &&
                Path.GetExtension(file) == Path.GetExtension(name))
            {
                names.Add(file);
            }

            names.AddRange(Aliases(path, real, name).Where(a => !names.Contains(a)));
        }

        // As systemd's dropin.c orders them: for each name, each directory from the highest priority down, under the
        // name, its template and its dash prefixes; the type-wide service.d last. A file name seen once is not applied
        // again from a later directory, and then everything applies in file-name order.
        var directories = names
            .SelectMany(n => path.SelectMany(d => Expansions(n).Select(e => Path.Combine(d, e + ".d"))))
            .Concat(path.Select(d => Path.Combine(d, Path.GetExtension(name)[1..] + ".d")));
        var seen = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var directory in directories)
        {
            if (!Directory.Exists(directory))
            {
                continue;
            }

            foreach (var file in Directory.EnumerateFileSystemEntries(directory, "*.conf"))
            {
                seen.TryAdd(Path.GetFileName(file), file);
            }
        }

        // A drop-in linked to /dev/null is masked: it shadows a lower one of its name and applies nothing.
        var dropIns = seen.OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => p.Value)
            .Where(f => RealOr(f) != "/dev/null")
            .ToList();
        return new UnitFiles(fragment, dropIns);
    }

    /// <summary>The other names a unit file goes by: each link in the search path that leads to it.</summary>
    /// <remarks>
    /// <para>As systemd's unit_file_build_name_map: every link directly in a search-path directory names the file it
    /// leads to, and unit_find_dropin_paths reads drop-ins under every one of those names -- how
    /// display-manager.service.d reaches gdm.service. Looking only from the enabled name's side missed a user's
    /// ~/.config/systemd/user/zz.service linked to a packaged x.service, whose zz.service.d replaced its ExecStart.</para>
    /// <para>An instance's aliases come from its template's: zz@.service linked to w@.service makes w@one.service
    /// also zz@one.service. A link of another type, or between a template and a plain unit, is no alias.</para>
    /// </remarks>
    private IEnumerable<string> Aliases(IReadOnlyList<string> path, string realFragment, string name)
    {
        if (!_aliases.TryGetValue(path, out var map))
        {
            map = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            foreach (var directory in path.Where(Directory.Exists))
            {
                foreach (var entry in Directory.EnumerateFileSystemEntries(directory).Order(StringComparer.Ordinal))
                {
                    if (Path.GetExtension(entry).Length > 1 && new FileInfo(entry).LinkTarget is not null && realPath(entry) is { } target)
                    {
                        (map.TryGetValue(target, out var names) ? names : map[target] = []).Add(Path.GetFileName(entry));
                    }
                }
            }

            _aliases[path] = map;
        }

        var instance = Template(name) is null ? null : name[(name.IndexOf('@', StringComparison.Ordinal) + 1)..name.LastIndexOf('.')];
        foreach (var alias in map.GetValueOrDefault(realFragment) ?? [])
        {
            if (Path.GetExtension(alias) != Path.GetExtension(name))
            {
                continue;
            }

            var aliasIsTemplate = alias.Contains("@.", StringComparison.Ordinal);
            if (instance is null && !aliasIsTemplate)
            {
                yield return alias;
            }
            else if (instance is not null && aliasIsTemplate)
            {
                yield return alias.Replace("@.", "@" + instance + ".", StringComparison.Ordinal);
            }
        }
    }

    /// <summary>Each search path's links, by the file they lead to; built once per path, as systemd builds its map once.</summary>
    private readonly Dictionary<IReadOnlyList<string>, Dictionary<string, List<string>>> _aliases = new(ReferenceEqualityComparer.Instance);

    /// <summary>The names a unit's drop-in directories go by: its own, its template's, each dash prefix's, then its type's.</summary>
    internal static IReadOnlyList<string> DropInNames(IReadOnlyList<string> names) =>
        names.SelectMany(Expansions).Append(Path.GetExtension(names[0])[1..]).Distinct(StringComparer.Ordinal).ToList();

    /// <summary>A name, its template, and its dash prefixes: a-b-c.service also takes a-b-.service.d and a-.service.d.</summary>
    private static IEnumerable<string> Expansions(string name)
    {
        yield return name;
        var suffix = Path.GetExtension(name);
        if (Template(name) is { } template)
        {
            yield return template;
            name = template;
        }

        var stem = name[..^suffix.Length];
        for (var dash = stem.LastIndexOf('-'); dash > 0; dash = stem.LastIndexOf('-', dash - 1))
        {
            if (dash + 1 < stem.Length)
            {
                yield return stem[..(dash + 1)] + suffix;
            }
        }
    }

    /// <summary>foo@.service for foo@bar.service; null when the name is not an instance.</summary>
    private static string? Template(string name)
    {
        var at = name.IndexOf('@', StringComparison.Ordinal);
        var dot = name.LastIndexOf('.');
        return at > 0 && at + 1 < dot ? name[..(at + 1)] + name[dot..] : null;
    }

    private string RealOr(string path) => realPath(path) ?? path;

    private static string? SafeRealPath(string path)
    {
        try
        {
            return LibC.RealPath(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
