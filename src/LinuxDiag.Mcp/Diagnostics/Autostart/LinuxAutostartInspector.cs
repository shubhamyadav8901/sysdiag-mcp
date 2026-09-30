using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Linux.External;
using LinuxDiag.Mcp.Linux.Packages;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Linux.Proc;

namespace LinuxDiag.Mcp.Diagnostics.Autostart;

public sealed class LinuxAutostartInspector(
    IExternalCommand commands, IPackageDatabaseSource packages, IPrivilegeProbe privileges, LinuxDiagOptions options)
    : IAutostartInspector
{
    internal static readonly string[] AllCategories =
        ["cron", "paths", "preload", "profiled", "rclocal", "services", "sockets", "timers", "userunits"];

    private static readonly Dictionary<string, string> UnitCategory = new(StringComparer.Ordinal)
    {
        [".service"] = "services",
        [".timer"] = "timers",
        [".socket"] = "sockets",
        [".path"] = "paths",
    };

    public async Task<AutostartAuditResult> AuditAsync(AutostartQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var categories = ParseCategories(query.Categories);
        var limitations = new List<string>();
        var entries = new List<AutostartEntry>();
        if (categories.Intersect(UnitCategory.Values).Any())
        {
            entries.AddRange(await SystemdAsync(commands, categories, options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false));
        }

        if (categories.Contains("userunits")) entries.AddRange(UserUnits(limitations));
        if (categories.Contains("cron")) entries.AddRange(Cron(limitations));
        if (categories.Contains("rclocal")) entries.AddRange(RcLocal());
        if (categories.Contains("profiled")) entries.AddRange(Files("profiled", "/etc/profile.d", "sourced by every login shell", SourcedByProfile));
        if (categories.Contains("preload")) entries.AddRange(Preload());

        var matched = entries
            .Where(e => string.IsNullOrWhiteSpace(query.NameFilter) ||
                        new[] { e.Entry, e.ImagePath, e.Location, e.Description, e.LaunchString, e.ScriptPath }
                            .Any(v => v?.Contains(query.NameFilter, StringComparison.OrdinalIgnoreCase) == true))
            .ToList();

        var verify = query.VerifyPackages || query.UnpackagedOnly || query.HidePackaged;
        if (verify)
        {
            var database = packages.Open();
            if (!database.Available)
            {
                limitations.Add("This machine has no dpkg database, so package ownership was not checked.");
            }
            else
            {
                matched = matched.Select(e => Verify(e, database.Owner, Md5)).ToList();
            }
        }

        var ordered = matched
            .Where(e => !Hidden(e, query))
            .OrderBy(e => e.Category, StringComparer.Ordinal)
            .ThenBy(e => e.Entry, StringComparer.Ordinal)
            .ToList();
        return new AutostartAuditResult(
            ordered.Take(options.MaxResults).ToList(), ordered.Count, ordered.Count > options.MaxResults, privileges.IsElevated,
            verify, ordered.Count(e => e.Packaged == false), ordered.Count(e => e.ImageMissing), limitations);
    }

    internal static IReadOnlyList<string> ParseCategories(string categories)
    {
        var names = (categories ?? "all").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(c => c.ToLowerInvariant())
            .ToList();
        if (names.Count == 0 || names.Contains("all"))
        {
            return AllCategories;
        }

        foreach (var name in names.Where(n => !AllCategories.Contains(n)))
        {
            throw new ArgumentException($"'{name}' is not a category. Use one or more of: all, {string.Join(", ", AllCategories)}.", nameof(categories));
        }

        return names.Distinct().Order(StringComparer.Ordinal).ToList();
    }

    /// <summary>Every file that decides what runs, each checked against its package: the unit, drop-ins, program, script.</summary>
    /// <remarks>
    /// The unit file alone is not enough: a packaged unit with a drop-in that overrides ExecStart runs whatever
    /// the drop-in says, and hiding it because the unit is packaged would hide exactly that backdoor.
    /// </remarks>
    /// <param name="md5">A file's MD5, or null when it could not be read.</param>
    internal static AutostartEntry Verify(AutostartEntry entry, Func<string, PackageFile?> owner, Func<string, string?> md5)
    {
        // A missing program is already flagged as ImageMissing; judging it would call it "not from a package".
        var files = new[] { entry.Location }
            .Concat(entry.DropIns)
            .Append(entry.ImageMissing ? null : entry.ImagePath)
            .Append(entry.ScriptPath)
            .OfType<string>()
            .Where(f => f.StartsWith('/'))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var findings = new List<string>();
        foreach (var file in files)
        {
            if (md5(file) is not { } actual)
            {
                findings.Add($"{file}: could not be read, so its package could not be checked.");
                continue;
            }

            var (verdict, detail) = DpkgDatabase.Judge(owner(file), actual);
            if (verdict is not PackageVerdict.Valid)
            {
                findings.Add($"{file}: {detail}");
            }
        }

        var program = entry.ImagePath is null ? null : owner(entry.ImagePath);
        return entry with { Package = program?.Package, Packaged = findings.Count == 0, PackageFindings = findings };
    }

    /// <summary>Hidden only when asked to, and only when every checked file matched its package.</summary>
    internal static bool Hidden(AutostartEntry entry, AutostartQuery query) =>
        (query.UnpackagedOnly && entry.Packaged != false) ||
        (query.HidePackaged && entry.Packaged == true);

    internal static async Task<List<AutostartEntry>> SystemdAsync(
        IExternalCommand commands, IReadOnlyList<string> categories, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var listed = await Run(commands, ["list-unit-files", "--no-legend", "--plain", "--no-pager",
            "--state=enabled,enabled-runtime,linked,linked-runtime,generated"], timeout, cancellationToken).ConfigureAwait(false);
        var files = listed.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => l.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0])
            .Where(u => UnitCategory.TryGetValue(Path.GetExtension(u), out var category) && categories.Contains(category))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        // A template (getty@.service) cannot be shown -- systemctl refuses it and fails the whole batch. What
        // runs is its instances (getty@tty1.service), which list-unit-files never lists, so they come from
        // list-units: every loaded instance of an enabled template.
        var templates = files.Where(IsTemplate).ToHashSet(StringComparer.Ordinal);
        var units = files.Where(u => !IsTemplate(u)).ToList();
        if (templates.Count > 0)
        {
            var loaded = await Run(commands, ["list-units", "--all", "--no-legend", "--plain", "--no-pager", "--type=service,timer,socket,path"],
                timeout, cancellationToken).ConfigureAwait(false);
            units.AddRange(loaded.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(l => l.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0])
                .Where(u => u.IndexOf('@', StringComparison.Ordinal) is var at and > 0 &&
                            templates.Contains(u[..(at + 1)] + Path.GetExtension(u)))
                .Distinct(StringComparer.Ordinal));
        }

        if (units.Count == 0)
        {
            return [];
        }

        var shown = await Show(commands, units, timeout, cancellationToken).ConfigureAwait(false);
        var triggered = shown.Values.SelectMany(u => u.List("Triggers")).Where(t => !shown.ContainsKey(t) && !IsTemplate(t)).Distinct(StringComparer.Ordinal).ToList();
        var targets = triggered.Count == 0 ? [] : await Show(commands, triggered, timeout, cancellationToken).ConfigureAwait(false);

        var entries = new List<AutostartEntry>();
        foreach (var name in units)
        {
            if (!shown.TryGetValue(name, out var unit))
            {
                continue;
            }

            // A timer, socket or path runs another unit; what runs is that unit's ExecStart.
            var runs = unit.List("Triggers").FirstOrDefault();
            var runner = runs is not null && (shown.GetValueOrDefault(runs) ?? targets.GetValueOrDefault(runs)) is { } other ? other : unit;
            var command = runner.All("ExecStart").Select(SystemctlShow.Command).FirstOrDefault(c => c is not null);
            var (_, script) = command is null ? (null, null) : LaunchCommand.Split(command.CommandLine);
            var description = unit["Description"];
            if (runs is not null)
            {
                description = $"{description} (runs {runs})";
            }

            // The unit a timer or socket runs decides what runs, so its own file is checked with the drop-ins:
            // an /etc override of a packaged timer's service must not pass because the timer is packaged.
            IEnumerable<string> runnerFiles = runner == unit ? [] : [runner["FragmentPath"] ?? string.Empty, .. runner.List("DropInPaths")];
            entries.Add(new AutostartEntry(
                UnitCategory[Path.GetExtension(name)], unit["FragmentPath"] ?? name, name, true, null, description,
                command?.Path, command?.CommandLine, script,
                unit.List("DropInPaths").Concat(runnerFiles).Where(f => f.Length > 0).ToList(),
                null, null, [], command is not null && !File.Exists(command.Path)));
        }

        return entries;
    }

    private static async Task<Dictionary<string, SystemdUnit>> Show(
        IExternalCommand commands, IReadOnlyList<string> units, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var byId = new Dictionary<string, SystemdUnit>(StringComparer.Ordinal);
        foreach (var chunk in units.Chunk(200))
        {
            // systemctl show exits 1 when any one unit in the batch cannot be shown, yet prints every other one:
            // the blocks it printed are the answer, and only an empty answer is a failure.
            var result = await commands.RunAsync(
                "systemctl", ["show", "--timestamp=utc", "-p", "Id,Description,FragmentPath,DropInPaths,ExecStart,Triggers,User", "--", .. chunk],
                timeout, cancellationToken).ConfigureAwait(false);
            if (result.ExitCode != 0 && string.IsNullOrWhiteSpace(result.StandardOutput))
            {
                throw new ExternalCommandException($"systemctl show failed: {result.StandardError.Trim()}");
            }

            var text = result.StandardOutput;

            // Blocks are matched by Id, not by the order they were asked for.
            foreach (var unit in SystemctlShow.Parse(text).Where(u => u["Id"] is not null))
            {
                byId[unit["Id"]!] = unit;
            }
        }

        return byId;
    }

    private static bool IsTemplate(string unit) => unit.Contains("@.", StringComparison.Ordinal);

    private static async Task<string> Run(IExternalCommand commands, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var result = await commands.RunAsync("systemctl", arguments, timeout, cancellationToken).ConfigureAwait(false);
        return result.ExitCode == 0
            ? result.StandardOutput
            : throw new ExternalCommandException($"systemctl {arguments[0]} failed: {result.StandardError.Trim()}");
    }

    private static IEnumerable<AutostartEntry> UserUnits(List<string> limitations)
    {
        var accounts = Passwd.Entries(ReadOrEmpty(ProcFiles.Passwd));
        var places = new List<(string? User, string? Home, string Directory)> { (null, null, "/etc/systemd/user") };
        places.AddRange(accounts.Where(a => a.Home.Length > 1).Select(a => ((string?)a.Name, (string?)a.Home, Path.Combine(a.Home, ".config/systemd/user"))));
        var unreadable = 0;
        foreach (var (user, home, directory) in places)
        {
            IEnumerable<string> links;
            try
            {
                // Directory.Exists says false for a directory behind one the server cannot search, so an
                // unreadable home is looked for explicitly rather than read as "no user units".
                if (!Directory.Exists(directory))
                {
                    if (home is not null && Directory.Exists(home))
                    {
                        _ = Directory.EnumerateFileSystemEntries(home).Any();
                    }

                    continue;
                }

                links = Directory.EnumerateDirectories(directory, "*.wants").SelectMany(Directory.EnumerateFileSystemEntries).ToList();
            }
            catch (UnauthorizedAccessException)
            {
                unreadable++;
                continue;
            }

            var lingering = user is not null && File.Exists(Path.Combine("/var/lib/systemd/linger", user));
            foreach (var link in links)
            {
                var target = new FileInfo(link).ResolveLinkTarget(returnFinalTarget: true)?.FullName ?? link;
                var execStart = ReadOrEmpty(target).Split('\n').Select(l => l.Trim())
                    .FirstOrDefault(l => l.StartsWith("ExecStart=", StringComparison.Ordinal))?[10..].TrimStart('-', '@', '+', '!', ':');
                var (program, script) = execStart is null ? (null, null) : LaunchCommand.Split(execStart);
                yield return new AutostartEntry(
                    "userunits", target, Path.GetFileName(link), true, user ?? "(every user)",
                    user is null ? "starts at every user's login" : lingering ? "starts at boot (lingering)" : "starts at the user's login",
                    program, execStart, script, [], null, null, [], program is not null && program.StartsWith('/') && !File.Exists(program));
            }
        }

        if (unreadable > 0)
        {
            limitations.Add($"{unreadable} home directories could not be read, so those users' units are missing; run the server as root.");
        }
    }

    private static IEnumerable<AutostartEntry> Cron(List<string> limitations)
    {
        var sources = new List<(string File, bool System, string? User)> { ("/etc/crontab", true, null) };
        sources.AddRange(Listing("/etc/cron.d").Select(f => (f, true, (string?)null)));
        var spool = "/var/spool/cron/crontabs";
        try
        {
            sources.AddRange(Listing(spool, throwOnDenied: true).Select(f => (f, false, (string?)Path.GetFileName(f))));
        }
        catch (UnauthorizedAccessException)
        {
            limitations.Add($"{spool} is readable only by root, so users' own crontabs are missing.");
        }

        foreach (var (file, system, owner) in sources)
        {
            foreach (var cron in CronTab.Parse(ReadOrEmpty(file), system))
            {
                var (program, script) = LaunchCommand.Split(cron.Command);
                yield return new AutostartEntry(
                    "cron", file, $"{cron.Schedule} {cron.Command}", true, cron.User ?? owner, $"schedule {cron.Schedule}",
                    program, cron.Command, script, [], null, null, [], program is not null && program.StartsWith('/') && !File.Exists(program));
            }
        }

        foreach (var period in new[] { "hourly", "daily", "weekly", "monthly" })
        {
            foreach (var entry in Files("cron", $"/etc/cron.{period}", $"run {period} by run-parts", RunByRunParts))
            {
                yield return entry;
            }
        }
    }

    private static IEnumerable<AutostartEntry> RcLocal()
    {
        const string path = "/etc/rc.local";
        if (File.Exists(path))
        {
            var executable = (File.GetUnixFileMode(path) & UnixFileMode.UserExecute) != 0;
            yield return new AutostartEntry("rclocal", path, "rc.local", executable, null, "run once at boot by rc-local.service",
                path, path, null, [], null, null, [], false);
        }
    }

    private static IEnumerable<AutostartEntry> Preload()
    {
        const string path = "/etc/ld.so.preload";
        foreach (var library in ReadOrEmpty(path).Split('\n').Select(l => l.Split('#')[0])
                     .SelectMany(l => l.Split([' ', '\t', ':'], StringSplitOptions.RemoveEmptyEntries)))
        {
            yield return new AutostartEntry("preload", path, library, true, null, "loaded into every dynamically linked program",
                library, null, null, [], null, null, [], !File.Exists(library));
        }
    }

    /// <summary>The files in a directory that actually run: run-parts skips names with a dot, /etc/profile sources only *.sh.</summary>
    private static IEnumerable<AutostartEntry> Files(string category, string directory, string description, Func<string, bool> runs) =>
        Listing(directory).Where(file => runs(Path.GetFileName(file))).Select(file => new AutostartEntry(
            category, file, Path.GetFileName(file), true, null, description, file, file, null, [], null, null, [], false));

    private static bool RunByRunParts(string name) => name.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-');

    private static bool SourcedByProfile(string name) => name.EndsWith(".sh", StringComparison.Ordinal);

    private static IEnumerable<string> Listing(string directory, bool throwOnDenied = false)
    {
        try
        {
            return Directory.Exists(directory) ? Directory.EnumerateFiles(directory).Order(StringComparer.Ordinal).ToList() : [];
        }
        catch (UnauthorizedAccessException) when (!throwOnDenied)
        {
            return [];
        }
    }

    private static string? Md5(string path)
    {
        try
        {
            return FileHashes.Compute(path).Md5;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
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
}
