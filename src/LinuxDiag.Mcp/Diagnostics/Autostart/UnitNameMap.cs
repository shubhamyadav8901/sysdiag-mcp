namespace LinuxDiag.Mcp.Diagnostics.Autostart;

/// <summary>
/// Which file a unit name loads and every name that file goes by, for one search path, worked out the way systemd's
/// unit_file_build_name_map and unit_file_find_fragment (src/shared/unit-file.c) do.
/// </summary>
/// <remarks>
/// <para>By name, not by where a link leads. A link directly in a search-path directory whose target, made absolute
/// and chased as systemd chases it (see <see cref="Chase"/>), is also in the search path is an alias: its name stands
/// for the target's name, which is then looked up like any other -- so the target need not exist where the link
/// points. A target chase fails on is ignored. Any other link is a "linked unit file", loaded by the link's own name
/// and nothing else. The first directory holding a name decides it, link or not, dangling or not.</para>
/// <para>Matching links by the file they lead to, as this audit first did, missed what systemd does with each case:
/// zz.service -> /etc/systemd/user/x.service, with x.service only in /usr/lib, dangles but is still x.service's
/// alias; zz@one.service -> w@.service names one instance; and /opt/real.service linked in as ll.service gives
/// real.service.d nothing. Each was checked against a live user manager's
/// <c>systemctl --user show -p Names,FragmentPath,DropInPaths</c>.</para>
/// </remarks>
internal sealed class UnitNameMap
{
    /// <summary>systemd's FOLLOW_MAX: an alias chain longer than this loads nothing, as a loop does.</summary>
    private const int FollowMax = 8;

    /// <summary>
    /// systemd's CHASE_MAX. chase counts it down before each link it follows and fails at zero, so a link target that
    /// passes through this many links is a loop, and ignored.
    /// </summary>
    private const int ChaseMax = 32;

    private static readonly HashSet<string> Types = new(StringComparer.Ordinal)
    {
        "service", "socket", "target", "device", "mount", "automount", "swap", "timer", "path", "slice", "scope",
    };

    /// <summary>unit_type_may_alias(): only these types may be aliased by a link.</summary>
    private static readonly HashSet<string> MayAlias = new(StringComparer.Ordinal)
    {
        "service", "socket", "target", "device", "timer", "path",
    };

    /// <summary>unit_type_may_template().</summary>
    private static readonly HashSet<string> MayTemplate = new(StringComparer.Ordinal)
    {
        "service", "socket", "target", "timer", "path",
    };

    /// <summary>Name to an absolute path (a unit file, or a linked file's link), or to another unit's name (an alias).</summary>
    private readonly Dictionary<string, string> _ids = new(StringComparer.Ordinal);

    /// <summary>A unit's name to the names that lead to it, its own included when a file has it.</summary>
    private readonly Dictionary<string, List<string>> _names = new(StringComparer.Ordinal);

    private UnitNameMap()
    {
    }

    private enum NameType
    {
        Invalid, Plain, Template, Instance,
    }

    /// <param name="path">The search path, highest priority first.</param>
    /// <param name="realPath">Where a path leads, links resolved; null when it leads nowhere.</param>
    internal static UnitNameMap Build(IReadOnlyList<string> path, Func<string, string?> realPath)
    {
        var map = new UnitNameMap();

        // As systemd's expanded_search_path: each directory as spelled and where it really is, so a link into a
        // directory that is itself reached through a link (NixOS's /etc) is still recognised as an alias.
        var expanded = new List<string>();
        foreach (var directory in path)
        {
            expanded.Add(directory);
            if (realPath(directory) is { } real && !expanded.Contains(real))
            {
                expanded.Add(real);
            }
        }

        foreach (var directory in path)
        {
            foreach (var entry in Entries(directory))
            {
                var name = Path.GetFileName(entry);
                if (Classify(name) == NameType.Invalid || map._ids.ContainsKey(name))
                {
                    continue;
                }

                var info = new FileInfo(entry);
                if (info.LinkTarget is { } target)
                {
                    // A target chase cannot resolve -- ".." past a missing directory, a loop -- is warned about and
                    // the link ignored, so a lower directory's file of the name loads.
                    if (Chase(Path.IsPathRooted(target) ? target : Path.Combine(directory, target)) is not { } simplified)
                    {
                        continue;
                    }

                    if (expanded.Any(d => simplified.StartsWith(d.TrimEnd('/') + "/", StringComparison.Ordinal)))
                    {
                        // An alias systemd refuses is not entered at all, so a lower directory's file of the name loads.
                        if (ValidAlias(name, Path.GetFileName(simplified)))
                        {
                            map._ids[name] = Path.GetFileName(simplified);
                        }
                    }
                    else
                    {
                        map._ids[name] = entry;
                    }
                }
                else if (info.Exists)
                {
                    map._ids[name] = entry;
                }
            }
        }

        foreach (var source in map._ids.Keys)
        {
            // A name that leads nowhere, or to a masked or empty file, is no other unit's alias.
            if (map.Get(source) is not { } file || NullOrEmpty(file, realPath))
            {
                continue;
            }

            var target = Path.GetFileName(file);
            if (Classify(target) == NameType.Template && Classify(source) == NameType.Instance)
            {
                // An instance linked to a template is an alias of that one instance: zz@one -> w@ names w@one.
                target = WithInstance(target, Instance(source));
            }

            (map._names.TryGetValue(target, out var names) ? names : map._names[target] = []).Add(source);
        }

        return map;
    }

    /// <summary>The file a unit name loads, null when none; and every other name the unit goes by.</summary>
    internal (string? Fragment, IReadOnlyList<string> Names) Find(string unit)
    {
        var type = Classify(unit);
        var instance = type == NameType.Instance ? Instance(unit) : null;
        var names = new List<string>();
        AddNames(unit, null);

        var fragment = Get(unit) ?? (type == NameType.Instance ? Get(Template(unit)) : null);
        if (fragment is not null && Path.GetFileName(fragment) is var basename && basename != unit)
        {
            AddNames(basename, basename);
        }

        return (fragment, names);

        void AddNames(string name, string? fragmentBasename)
        {
            // A template is not a name of its own instances; an instance's fragment name, a template, is instantiated
            // as systemd does when it merges the names.
            if (type != NameType.Template)
            {
                Add(type == NameType.Instance && Classify(name) == NameType.Template ? WithInstance(name, instance!) : name);
            }

            foreach (var alias in _names.GetValueOrDefault(name) ?? [])
            {
                if (type == NameType.Instance && Classify(alias) == NameType.Template)
                {
                    // An instance of a template alias that has a file of its own is a different unit, not this one.
                    var aliasInstance = WithInstance(alias, instance!);
                    if (fragmentBasename is not null && Get(aliasInstance) is { } own && Path.GetFileName(own) != fragmentBasename)
                    {
                        continue;
                    }

                    Add(aliasInstance);
                }
                else
                {
                    Add(alias);
                }
            }
        }

        void Add(string name)
        {
            if (!names.Contains(name))
            {
                names.Add(name);
            }
        }
    }

    /// <summary>unit_ids_map_get(): follow aliases by name to an absolute path; an instance may fall to its template.</summary>
    private string? Get(string name)
    {
        string? id = null;
        for (var hop = 0; hop < FollowMax; hop++)
        {
            if (!_ids.TryGetValue(id ?? name, out var next))
            {
                if (id is null || Classify(id) != NameType.Instance || !_ids.TryGetValue(Template(id), out next))
                {
                    return null;
                }
            }

            if (next.StartsWith('/'))
            {
                return next;
            }

            id = next;
        }

        return null;
    }

    /// <summary>A search-path directory's entries; one that cannot be read is skipped, as systemd skips it.</summary>
    private static IEnumerable<string> Entries(string directory)
    {
        try
        {
            return Directory.Exists(directory)
                ? Directory.EnumerateFileSystemEntries(directory).Order(StringComparer.Ordinal).ToList()
                : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    /// <summary>
    /// chase(CHASE_NOFOLLOW|CHASE_NONEXISTENT) on an absolute link target, as unit_file_resolve_symlink calls it: null
    /// where that fails and systemd ignores the link.
    /// </summary>
    /// <remarks>
    /// <para>Walked a component at a time: each one that exists is resolved where it is, a link on the way followed
    /// and a ".." taken from the directory reached, never from the spelling; the last component, the unit's own name,
    /// is never followed. At the first component that does not exist the rest is appended as written, unless it holds
    /// a "..", which chase refuses.</para>
    /// <para>Not realpath(3) of the target's directory, falling back to folding it as text where that is null, as this
    /// first did. realpath gives up on the whole directory when any part of it is missing, while chase still goes
    /// through the part that exists: with ~/lnk -> /usr/lib/systemd/user, zz.service -> ~/lnk/nope/x.service is
    /// /usr/lib/systemd/user/nope/x.service to systemd -- in the search path, so an alias of x.service, whose
    /// ExecStart zz.service.d then replaced -- while the text, ~/lnk/nope/x.service, lay outside it. A link that
    /// itself leads nowhere is followed the same way, where realpath gives up on it too.</para>
    /// <para>So it reads each link itself rather than asking the injected realPath for the longest prefix that
    /// resolves: that prefix stops before a dangling link on the way, which chase opens without following, reads
    /// and goes through.</para>
    /// </remarks>
    private static string? Chase(string target)
    {
        var done = "/";
        var todo = new Stack<string>();
        Push(target);
        var hops = 0;
        try
        {
            while (todo.TryPop(out var part))
            {
                if (part == "..")
                {
                    // done holds no link, so its parent is where the kernel's ".." goes; above "/" is "/".
                    done = Path.GetDirectoryName(done) ?? done;
                    continue;
                }

                var next = Path.Combine(done, part);
                var last = todo.Count == 0;
                var link = new FileInfo(next).LinkTarget;
                if (link is not null && !last)
                {
                    if (++hops >= ChaseMax)
                    {
                        return null;
                    }

                    // An absolute target starts again from "/"; a relative one from the directory holding the link.
                    if (link.StartsWith('/'))
                    {
                        done = "/";
                    }

                    Push(link);
                }
                else if (link is not null || Directory.Exists(next) || (last && File.Exists(next)))
                {
                    done = next;
                }
                else if (File.Exists(next))
                {
                    // A file with more to come is ENOTDIR, which chase fails on; only ENOENT is let through.
                    return null;
                }
                else
                {
                    return todo.Contains("..") ? null : Path.Join([next, .. todo]);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        return done;

        // "." is skipped wherever it stands, and comparing against the search path skips it too, so it is dropped here.
        void Push(string path)
        {
            var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            for (var i = parts.Length - 1; i >= 0; i--)
            {
                if (parts[i] != ".")
                {
                    todo.Push(parts[i]);
                }
            }
        }
    }

    /// <summary>null_or_empty_path(): a file that is missing, a device such as /dev/null, or empty.</summary>
    private static bool NullOrEmpty(string path, Func<string, string?> realPath)
    {
        if (realPath(path) is not { } real || real.StartsWith("/dev/", StringComparison.Ordinal))
        {
            return true;
        }

        var info = new FileInfo(real);
        return !info.Exists || info.Length == 0;
    }

    /// <summary>unit_validate_alias_symlink_or_warn(): which links systemd accepts as an alias.</summary>
    private static bool ValidAlias(string source, string target)
    {
        var sourceType = Classify(source);
        var suffix = Path.GetExtension(source)[1..];
        if (!MayAlias.Contains(suffix) || (sourceType != NameType.Plain && !MayTemplate.Contains(suffix)) || source == target)
        {
            return false;
        }

        var targetType = Classify(target);
        if (targetType == NameType.Invalid || Path.GetExtension(target) != Path.GetExtension(source))
        {
            return false;
        }

        if (targetType != sourceType && !(sourceType == NameType.Instance && targetType == NameType.Template))
        {
            return false;
        }

        return targetType != NameType.Instance || Instance(source) == Instance(target);
    }

    /// <summary>unit_name_is_valid(): a known type after the last dot, valid characters, '@' never first.</summary>
    private static NameType Classify(string name)
    {
        var dot = name.LastIndexOf('.');
        if (name.Length is 0 or >= 256 || dot <= 0 || !Types.Contains(name[(dot + 1)..]))
        {
            return NameType.Invalid;
        }

        var stem = name[..dot];
        if (stem.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is ':' or '-' or '_' or '.' or '\\' or '@')))
        {
            return NameType.Invalid;
        }

        var at = stem.IndexOf('@', StringComparison.Ordinal);
        return at switch
        {
            < 0 => NameType.Plain,
            0 => NameType.Invalid,
            _ when at == stem.Length - 1 => NameType.Template,
            _ => NameType.Instance,
        };
    }

    private static string Instance(string name) => name[(name.IndexOf('@', StringComparison.Ordinal) + 1)..name.LastIndexOf('.')];

    private static string Template(string name) => name[..(name.IndexOf('@', StringComparison.Ordinal) + 1)] + name[name.LastIndexOf('.')..];

    private static string WithInstance(string template, string instance) =>
        template[..(template.IndexOf('@', StringComparison.Ordinal) + 1)] + instance + template[template.LastIndexOf('.')..];
}
