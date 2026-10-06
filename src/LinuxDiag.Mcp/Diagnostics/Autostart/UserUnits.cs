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
/// <param name="readOwnedBy">
/// As <paramref name="read"/>, but null when the file opened is not owned by the given user ID -- for a file whose
/// content, not one setting's value, is reported.
/// </param>
/// <param name="realPath">Where a path leads, links resolved; null when it leads nowhere.</param>
/// <param name="root">Prefixed to every system directory; empty except under test.</param>
internal sealed class UserUnits(
    Func<string, string> read, Func<string, long, string?> readOwnedBy, Func<string, string?> realPath, string root = "")
{
    /// <summary>What systemd's env_name_is_valid() accepts; it ignores any other assignment.</summary>
    private static readonly System.Text.RegularExpressions.Regex VariableName = new("^[A-Za-z_][A-Za-z0-9_]*$",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private static readonly Dictionary<string, string> TriggerSections = new(StringComparer.Ordinal)
    {
        [".timer"] = "Timer", [".socket"] = "Socket", [".path"] = "Path",
    };

    /// <summary>The server's own readers: <see cref="LinuxAutostartInspector.ReadConfiguration"/> and realpath(3).</summary>
    internal static UserUnits Reading(string root = "") =>
        new(LinuxAutostartInspector.ReadConfiguration, LinuxAutostartInspector.ReadConfigurationOwnedBy, SafeRealPath, root);

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
            var when = lingering(account.Name) ? "starts at boot (lingering)" : "starts at the user's login";
            bool any;
            List<AutostartEntry> environment;
            try
            {
                environment = UserEnvironment(account, when);
                any = personal.Any(Directory.Exists);
                if (!any && environment.Count == 0 && Directory.Exists(account.Home))
                {
                    _ = Directory.EnumerateFileSystemEntries(account.Home).Any();
                }
            }
            catch (UnauthorizedAccessException)
            {
                unreadable++;
                continue;
            }

            foreach (var entry in environment)
            {
                yield return entry;
            }

            if (!any)
            {
                continue;
            }

            var path = SearchPath(account.Home, account.UserId);
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

    /// <summary>The files in a user's home that set the environment of what their systemd manager runs, one entry each.</summary>
    /// <remarks>
    /// <para>No unit file or drop-in is needed to change what a packaged user unit does: the manager hands
    /// ~/.config/environment.d/*.conf (through its environment generator) and DefaultEnvironment= in
    /// ~/.config/systemd/user.conf and user.conf.d to every unit it starts, so LD_PRELOAD there runs the user's code
    /// inside each one, and PATH chooses what a relative ExecStart runs. Folding these into every unit's drop-ins
    /// would mark every packaged unit of that user as changed and still not say why; an entry of their own names
    /// the file and what it sets, and -- never a package's -- is never hidden by unpackagedOnly.</para>
    /// <para>ManagerEnvironment= is the manager's own, not its units', but the generators it runs inherit it, and
    /// their output is what the units get. Values are not shown: these files hold tokens as often as paths.</para>
    /// <para>Names are reported, so a file is read only when the user owns it. A link or hard link here can lead
    /// anywhere and the server is root: a link to /root/.ssh/id_ed25519 had the key's padded base64 line reported as
    /// a "variable", and a name filter alone would not stop that line, which is a valid name. A file another account
    /// owns is still an entry -- what it sets is unknown, which is not the same as nothing -- but its content is
    /// not read. Only names systemd would accept are reported; it ignores any other assignment.</para>
    /// </remarks>
    private List<AutostartEntry> UserEnvironment(PasswdEntry account, string when)
    {
        var (home, user) = (account.Home, account.Name);
        IEnumerable<string> Conf(string directory) =>
            Directory.Exists(directory) ? Directory.EnumerateFiles(directory, "*.conf").Order(StringComparer.Ordinal) : [];

        var files = Conf(Path.Combine(home, ".config/environment.d")).Select(f => (f, "environment.d/" + Path.GetFileName(f)))
            .Concat(new[] { Path.Combine(home, ".config/systemd/user.conf") }.Where(File.Exists).Select(f => (f, "user.conf")))
            .Concat(Conf(Path.Combine(home, ".config/systemd/user.conf.d")).Select(f => (f, "user.conf.d/" + Path.GetFileName(f))));

        var entries = new List<AutostartEntry>();
        foreach (var (file, name) in files)
        {
            if (readOwnedBy(file, account.UserId) is not { } text)
            {
                entries.Add(new AutostartEntry(
                    "userunits", file, name, true, user,
                    $"{when}: owned by another account, not this user, so its content is not read and what it sets is not shown",
                    null, null, null, [], null, null, [], false));
                continue;
            }

            var reaches = new List<string>();
            if (name.StartsWith("environment.d/", StringComparison.Ordinal))
            {
                Reach(reaches, UnitFile.EnvironmentFileKeys(text), "for every unit this user's systemd manager starts");
            }
            else
            {
                Reach(reaches, UnitFile.Values([text], "Manager", "DefaultEnvironment").SelectMany(UnitFile.EnvironmentNames),
                    "for every unit this user's systemd manager starts");
                Reach(reaches, UnitFile.Values([text], "Manager", "ManagerEnvironment").SelectMany(UnitFile.EnvironmentNames),
                    "for this user's systemd manager itself and the generators it runs");
            }

            if (reaches.Count > 0)
            {
                entries.Add(new AutostartEntry(
                    "userunits", file, name, true, user, $"{when}: {string.Join("; ", reaches)} (values not shown)",
                    null, null, null, [], null, null, [], false));
            }
        }

        return entries;

        static void Reach(List<string> reaches, IEnumerable<string> names, string reach)
        {
            var set = names.Where(n => VariableName.IsMatch(n)).Distinct(StringComparer.Ordinal).ToList();
            if (set.Count > 0)
            {
                reaches.Add($"sets {string.Join(", ", set)} {reach}");
            }
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
        // The file and every name it goes by come from systemd's name map, and drop-ins apply under each name: that is
        // how display-manager.service.d reaches gdm.service, and how a user's zz.service.d reached a packaged x.service.
        if (!_maps.TryGetValue(path, out var map))
        {
            _maps[path] = map = UnitNameMap.Build(path, realPath);
        }

        var (fragment, aliases) = map.Find(name);
        var names = aliases.Prepend(name).Distinct(StringComparer.Ordinal).ToList();

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

    /// <summary>Each search path's name map; built once per path, as systemd builds its map once.</summary>
    private readonly Dictionary<IReadOnlyList<string>, UnitNameMap> _maps = new(ReferenceEqualityComparer.Instance);

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
