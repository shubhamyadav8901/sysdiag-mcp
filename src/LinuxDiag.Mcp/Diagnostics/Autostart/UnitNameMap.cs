namespace LinuxDiag.Mcp.Diagnostics.Autostart;

/// <summary>
/// Which file a unit name loads and every name that file goes by, for one search path, worked out the way systemd's
/// unit_file_build_name_map and unit_file_find_fragment (src/shared/unit-file.c) do.
/// </summary>
/// <remarks>
/// <para>By name, not by where a link leads. A link directly in a search-path directory whose target, made absolute
/// and with "." and ".." folded, is also in the search path is an alias: its name stands for the target's name, which
/// is then looked up like any other -- so the target need not exist where the link points. Any other link is a
/// "linked unit file", loaded by the link's own name and nothing else. The first directory holding a name decides
/// it, link or not, dangling or not.</para>
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
                    var simplified = Simplify(Path.IsPathRooted(target) ? target : Path.Combine(directory, target), realPath);
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
    /// A link target with "." and ".." folded the way chase(CHASE_NOFOLLOW|CHASE_NONEXISTENT) folds them: the
    /// directories on the way resolved where they exist, the last component -- the unit's name -- never followed.
    /// </summary>
    private static string Simplify(string target, Func<string, string?> realPath)
    {
        var name = Path.GetFileName(target);
        if (name is "" or "." or ".." || Path.GetDirectoryName(target) is not { } directory)
        {
            return Path.GetFullPath(target);
        }

        return Path.Combine(realPath(directory) ?? Path.GetFullPath(directory), name);
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
