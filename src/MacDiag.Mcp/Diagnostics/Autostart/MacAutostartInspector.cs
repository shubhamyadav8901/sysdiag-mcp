using System.Globalization;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Services;
using MacDiag.Mcp.Hosting;
using MacDiag.Mcp.Mac.Launchd;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Autostart;

/// <summary>What starts on its own on this Mac, the program each runs, and whether another account could change it.</summary>
/// <remarks>
/// <para>"Could another account change what runs" is the question persistence hunting asks, so every file that
/// decides what runs -- the plist or crontab, the program, the script an interpreter runs -- and every directory
/// above each is statted. A file is judged against the account the job runs as: a daemon's program may belong to
/// root or to its UserName, a user's agent to that user, and a /Library agent's program to anyone (it runs as
/// whoever logs in, and drag-installed apps belong to the user who dragged them). Write access for wheel or admin
/// does not count, because admins can become root anyway.</para>
/// <para>hideApple judges where an entry comes from, never what it calls itself: whoever writes a plist chooses its
/// label, so a planted /Library/LaunchDaemons/com.apple.updater.plist must show. An entry is hidden only when its
/// file is on the sealed system volume (/System). Not by its program's signature either: Apple's own programs --
/// curl, osascript, sh -c -- run whatever a planted plist tells them to.</para>
/// </remarks>
public sealed class MacAutostartInspector(IExternalCommand commands, MacDiagOptions options, IPrivilegeProbe privilege) : IAutostartInspector
{
    internal static readonly string[] Categories =
        ["daemons", "agents", "useragents", "cron", "periodic", "loginhooks", "authplugins", "sysext", "kext", "btm"];

    internal const string AppleExtensionsNote =
        "Apple's kernel and system extensions are hidden by their bundle identifier, which the extension declares; pass hideApple false to see them.";

    private const string BtmLocation = "Background Task Management (sfltool dumpbtm)";

    internal const string AclNote =
        "Write access granted through an ACL is not checked; effective_access answers that for one path.";

    private const string SealedVolume = "/System/";
    private const int AnyExecuteBit = 0b001_001_001;

    private static readonly string[] Interpreters =
        ["/bin/sh", "/bin/bash", "/bin/zsh", "/bin/csh", "/bin/tcsh", "/bin/ksh", "/bin/dash", "/usr/bin/perl", "/usr/bin/python3",
         "/usr/bin/ruby", "/usr/bin/osascript", "/usr/bin/env"];

    private static readonly string[] PeriodicDirectories =
        ["/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly",
         "/usr/local/etc/periodic/daily", "/usr/local/etc/periodic/weekly", "/usr/local/etc/periodic/monthly"];

    private static readonly string[] PeriodicLocalFiles = ["/etc/daily.local", "/etc/weekly.local", "/etc/monthly.local"];

    private static readonly string[] LoginWindowPreferences =
        ["/Library/Preferences/com.apple.loginwindow.plist", "/var/root/Library/Preferences/com.apple.loginwindow.plist"];

    private static readonly IReadOnlySet<int> RootOnly = new HashSet<int> { 0 };

    internal Func<IEnumerable<string>> ListHomes { get; init; } = DefaultHomes;

    /// <summary>The files and directories directly inside a directory, as full paths; empty when it does not exist.</summary>
    internal Func<string, IEnumerable<string>> ListEntries { get; init; } = DefaultEntries;

    internal Func<string, bool> FileExists { get; init; } = path => File.Exists(path) || Directory.Exists(path);

    /// <summary>A text file's content, or null when it does not exist.</summary>
    internal Func<string, string?> ReadText { get; init; } = path => File.Exists(path) ? File.ReadAllText(path) : null;

    internal Func<string, string> Resolve { get; init; } = StartupPermissions.RealPath;

    private IExternalCommand Runner => commands;

    private MacDiagOptions Options => options;

    public async Task<AutostartAuditResult> AuditAsync(AutostartQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var wanted = Parse(query.Categories);
        var run = new Run(this, query, privilege.IsElevated, cancellationToken);
        if (wanted.Contains("daemons")) await run.DaemonsAsync().ConfigureAwait(false);
        if (wanted.Contains("agents")) await run.AgentsAsync().ConfigureAwait(false);
        if (wanted.Contains("useragents")) await run.UserAgentsAsync().ConfigureAwait(false);
        if (wanted.Contains("cron")) await run.CronAsync().ConfigureAwait(false);
        if (wanted.Contains("periodic")) run.Periodic();
        if (wanted.Contains("loginhooks")) await run.LoginHooksAsync().ConfigureAwait(false);
        if (wanted.Contains("authplugins")) run.AuthorizationPlugins();
        if (wanted.Contains("sysext")) await run.SystemExtensionsAsync().ConfigureAwait(false);
        if (wanted.Contains("kext")) await run.KextsAsync().ConfigureAwait(false);

        // Last: a legacy daemon or agent it lists may already be an entry from its plist.
        if (wanted.Contains("btm")) await run.BackgroundTasksAsync().ConfigureAwait(false);
        return await run.FinishAsync().ConfigureAwait(false);
    }

    internal static IReadOnlySet<string> Parse(string categories)
    {
        var names = (string.IsNullOrWhiteSpace(categories) ? "all" : categories)
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(n => n.ToLowerInvariant())
            .ToList();
        var unknown = names.Where(n => n != "all" && !Categories.Contains(n)).ToList();
        if (unknown.Count > 0)
        {
            throw new ArgumentException(
                $"Unknown autostart categor{(unknown.Count == 1 ? "y" : "ies")} '{string.Join("', '", unknown)}'. " +
                $"Use one or more of: all, {string.Join(", ", Categories)}.", nameof(categories));
        }

        return names.Contains("all") ? Categories.ToHashSet() : names.ToHashSet();
    }

    /// <param name="SourceOwners">Who may own the file that makes it start.</param>
    /// <param name="ImageOwners">Who may own the program and script; null means any account.</param>
    private sealed record Candidate(
        string Category, string Location, string Entry, bool Enabled, string? Profile, string? Description, string? Image,
        string? LaunchString, string? Script, IReadOnlySet<int> SourceOwners, IReadOnlySet<int>? ImageOwners,
        bool RequireExecutable = false, string? Problem = null);

    /// <summary>One audit's state: what was found so far, and what could not be read.</summary>
    private sealed class Run(MacAutostartInspector owner, AutostartQuery query, bool elevated, CancellationToken cancellationToken)
    {
        private readonly List<Candidate> _found = [];
        private readonly List<string> _limitations = [];
        private readonly List<string> _unreadable = [];
        private readonly Dictionary<string, IReadOnlyDictionary<string, bool>> _overrides = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int?> _uids = new(StringComparer.Ordinal);
        private Dictionary<string, StatLine>? _homes;
        private bool _hiddenExtensions;
        private readonly HashSet<string> _denied = new(StringComparer.Ordinal);

        /// <summary>A listing command's output, or null with the failure named as a limitation.</summary>
        private async Task<string?> ListingAsync(string program, string[] arguments, string command)
        {
            ExternalResult result;
            try
            {
                result = await Commands.RunAsync(program, arguments, Timeout, cancellationToken).ConfigureAwait(false);
            }
            catch (ExternalCommandException ex)
            {
                _limitations.Add($"{command} did not finish ({ex.Message}), so what it lists is missing.");
                return null;
            }

            if (result.ExitCode == 0)
            {
                return result.StandardOutput;
            }

            var reason = result.StandardError.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0) ?? $"exit {result.ExitCode}";
            _limitations.Add($"{command} failed ({reason}), so what it lists is missing.");
            return null;
        }

        private IExternalCommand Commands => owner.Runner;

        private TimeSpan Timeout => owner.Options.ExternalToolTimeout;

        public Task DaemonsAsync() =>
            LaunchdAsync("daemons", LaunchdPlists.DaemonDirectories, "system", null, RootOnly, async plist =>
                plist.String("UserName") is { } user && await UidAsync(user).ConfigureAwait(false) is { } uid
                    ? new HashSet<int> { 0, uid }
                    : RootOnly);

        public async Task AgentsAsync()
        {
            var console = await ConsoleUserAsync().ConfigureAwait(false);
            await LaunchdAsync("agents", LaunchdPlists.AgentDirectories, console is > 0 ? $"gui/{console}" : null, null, RootOnly, _ => Task.FromResult<IReadOnlySet<int>?>(null))
                .ConfigureAwait(false);
        }

        public async Task UserAgentsAsync()
        {
            // Directory.Exists says false for a directory it may not search, so another user's 0700 Library looks empty.
            if (!elevated)
            {
                _limitations.Add("The server is not running as root, so other users' LaunchAgents, in homes it cannot read, are not listed.");
            }

            foreach (var home in await HomesAsync().ConfigureAwait(false))
            {
                var name = home.Key[(home.Key.LastIndexOf('/') + 1)..];
                IReadOnlySet<int> owners = new HashSet<int> { 0, home.Value.Uid };
                await LaunchdAsync("useragents", [$"{home.Key}/Library/LaunchAgents"], $"gui/{home.Value.Uid}", name, owners, _ => Task.FromResult<IReadOnlySet<int>?>(owners))
                    .ConfigureAwait(false);
            }
        }

        public async Task CronAsync()
        {
            if (Read("/etc/crontab") is { } system)
            {
                foreach (var job in CronLines.Parse(system, hasUserField: true))
                {
                    var uid = job.User is null ? null : await UidAsync(job.User).ConfigureAwait(false);
                    AddCron("/etc/crontab", job, job.User, RootOnly, uid is { } u ? new HashSet<int> { 0, u } : RootOnly);
                }
            }

            const string Tabs = "/usr/lib/cron/tabs";
            if (!elevated)
            {
                _limitations.Add($"Users' crontabs in {Tabs} are readable only by root, so they are not listed.");
                return;
            }

            foreach (var tab in List(Tabs))
            {
                var user = tab[(tab.LastIndexOf('/') + 1)..];
                if (StatLines.HasControlCharacter(tab))
                {
                    _found.Add(new Candidate("cron", tab, user, true, null, null, null, null, null, RootOnly, RootOnly, Problem: "its name contains a control character"));
                    continue;
                }

                if (Read(tab) is not { } text)
                {
                    continue;
                }

                var uid = await UidAsync(user).ConfigureAwait(false);
                IReadOnlySet<int> owners = uid is { } u ? new HashSet<int> { 0, u } : RootOnly;
                foreach (var job in CronLines.Parse(text, hasUserField: false))
                {
                    AddCron(tab, job, user, owners, owners);
                }
            }
        }

        public void Periodic()
        {
            foreach (var file in PeriodicDirectories.SelectMany(List))
            {
                var name = file[(file.LastIndexOf('/') + 1)..];
                _found.Add(new Candidate("periodic", file, name, true, null, file[..file.LastIndexOf('/')], file, file, null, RootOnly, RootOnly,
                    RequireExecutable: true, Problem: StatLines.HasControlCharacter(file) ? "its name contains a control character" : null));
            }

            foreach (var file in PeriodicLocalFiles.Where(owner.FileExists))
            {
                _found.Add(new Candidate("periodic", file, file[(file.LastIndexOf('/') + 1)..], true, null, "run by periodic(8)", file, file, null, RootOnly, RootOnly));
            }
        }

        public async Task LoginHooksAsync()
        {
            foreach (var preferences in LoginWindowPreferences)
            {
                if (preferences.StartsWith("/var/root/", StringComparison.Ordinal) && !elevated)
                {
                    _limitations.Add($"{preferences} is in root's home, readable only by root, so its login and logout hooks are not listed.");
                    continue;
                }

                if (!owner.FileExists(preferences) || await ReadPlistAsync(preferences).ConfigureAwait(false) is not { } plist)
                {
                    continue;
                }

                foreach (var hook in new[] { "LoginHook", "LogoutHook" })
                {
                    if (plist.String(hook) is { Length: > 0 } script)
                    {
                        _found.Add(new Candidate("loginhooks", preferences, hook, true, null, hook == "LoginHook" ? "at every login, as root" : "at every logout, as root",
                            script, script, null, RootOnly, RootOnly));
                    }
                }
            }
        }

        public void AuthorizationPlugins()
        {
            foreach (var bundle in List("/Library/Security/SecurityAgentPlugins").Where(p => p.EndsWith(".bundle", StringComparison.Ordinal)))
            {
                _found.Add(new Candidate("authplugins", bundle, bundle[(bundle.LastIndexOf('/') + 1)..], true, null, "loaded by the login and authorization window",
                    bundle, null, null, RootOnly, RootOnly, Problem: StatLines.HasControlCharacter(bundle) ? "its name contains a control character" : null));
            }
        }

        public async Task SystemExtensionsAsync()
        {
            const string Command = "systemextensionsctl list";
            if (await ListingAsync("systemextensionsctl", ["list"], Command).ConfigureAwait(false) is not { } text)
            {
                return;
            }

            var extensions = SystemExtensions.Parse(text);
            if (extensions.Count == 0 && !SystemExtensions.SaysNone(text) && text.Trim().Length > 0)
            {
                _limitations.Add($"{Command} printed nothing this server recognises, so system extensions are not listed.");
            }

            foreach (var extension in extensions)
            {
                if (query.HideApple && (extension.BundleId.StartsWith("com.apple.", StringComparison.Ordinal) || extension.TeamId == "Apple"))
                {
                    _hiddenExtensions = true;
                    continue;
                }

                _found.Add(new Candidate("sysext", Command, extension.BundleId, extension.Enabled, null,
                    $"{extension.Kind}: {extension.Name ?? extension.BundleId} {extension.Version}, team {extension.TeamId ?? "none"} [{extension.State}]",
                    null, null, null, RootOnly, RootOnly));
            }
        }

        public async Task KextsAsync()
        {
            const string Command = "kmutil showloaded";
            if (await ListingAsync("kmutil", ["showloaded"], Command).ConfigureAwait(false) is not { } text)
            {
                return;
            }

            var kexts = KextList.Parse(text);
            if (kexts.Count == 0 && KextList.HasUnrecognisedLines(text))
            {
                _limitations.Add($"{Command} printed nothing this server recognises, so kernel extensions are not listed.");
            }

            foreach (var kext in kexts)
            {
                if (query.HideApple && kext.BundleId.StartsWith("com.apple.", StringComparison.Ordinal))
                {
                    _hiddenExtensions = true;
                    continue;
                }

                _found.Add(new Candidate("kext", Command, kext.BundleId, true, null, $"loaded, version {kext.Version}", null, null, null, RootOnly, RootOnly));
            }
        }

        public async Task BackgroundTasksAsync()
        {
            const string Command = "sfltool dumpbtm";
            if (!elevated)
            {
                _limitations.Add($"Background Task Management ({Command}) needs root, so its login items and helpers are not listed.");
                return;
            }

            if (await ListingAsync("sfltool", ["dumpbtm"], Command).ConfigureAwait(false) is not { } text)
            {
                return;
            }

            var items = BtmDump.Parse(text);
            if (items.Count == 0 && text.Trim().Length > 0 && !text.Contains("Records for UID", StringComparison.Ordinal))
            {
                _limitations.Add($"{Command} printed nothing this server recognises, so Background Task Management items are not listed.");
            }

            var listed = _found.Select(c => c.Image).OfType<string>().ToHashSet(StringComparer.Ordinal);
            foreach (var item in items)
            {
                var name = item.Name ?? item.Identifier ?? "(unnamed)";
                if (item.Missing.Count > 0)
                {
                    _limitations.Add($"A Background Task Management item ({name}) did not report: {string.Join(", ", item.Missing)}.");
                }

                var legacy = item.Type?.StartsWith("legacy", StringComparison.Ordinal) == true;
                if ((legacy && item.ExecutablePath is { } path && listed.Contains(path)) ||
                    (query.HideApple && item.ExecutablePath?.StartsWith(SealedVolume, StringComparison.Ordinal) == true))
                {
                    continue;
                }

                var runsAsRoot = item.Type?.Contains("daemon", StringComparison.Ordinal) == true;
                _found.Add(new Candidate("btm", BtmLocation, name, item.Enabled, item.Uid > 0 ? $"uid {item.Uid}" : null,
                    $"{item.Type ?? "unknown type"} [{string.Join(", ", item.Disposition)}]{(item.Url is { } url ? $" from {url}" : string.Empty)}",
                    item.ExecutablePath, item.ExecutablePath, null, RootOnly, runsAsRoot ? RootOnly : null));
            }
        }

        public async Task<AutostartAuditResult> FinishAsync()
        {
            if (_hiddenExtensions)
            {
                _limitations.Add(AppleExtensionsNote);
            }

            var matched = _found.Where(Matches).ToList();
            var stats = await StatAllAsync(matched).ConfigureAwait(false);

            var entries = new List<AutostartEntry>();
            var verify = query.VerifySignatures || query.UnsignedOnly;
            var signatures = new Dictionary<string, (bool? Signed, string Detail)>(StringComparer.Ordinal);
            foreach (var candidate in matched)
            {
                // periodic(8) runs what [ -x ] accepts, which follows a link: judge the file it leads to. A name that
                // could not be statted is flagged by Judge, never dropped here.
                if (candidate.RequireExecutable && candidate.Problem is null && !Executable(candidate.Location, stats))
                {
                    continue;
                }

                var findings = new List<string>();
                var writable = Judge(candidate, stats, findings, out var missing);

                bool? signed = null;
                string? detail = null;
                if (verify && candidate.Image is { } image && !missing && candidate.Problem is null)
                {
                    if (_denied.Contains(image) || (candidate.Script is { } denied && _denied.Contains(denied)))
                    {
                        // Not judged is neither unsigned nor signed: codesign cannot read it any more than stat could.
                        (signed, detail) = (null, "could not be examined (permission denied)");
                    }
                    else if (candidate.Script is not null)
                    {
                        (signed, detail) = (false, "a script; its interpreter's signature says nothing about it");
                    }
                    else if (Interpreters.Contains(image, StringComparer.Ordinal))
                    {
                        // sh -c, osascript -e, python3 -c, env: the code that runs is in the arguments, and nobody signed it.
                        (signed, detail) = (false, "an interpreter running code from its arguments; what it runs is not signed");
                    }
                    else
                    {
                        if (!signatures.TryGetValue(image, out var known))
                        {
                            known = await SignatureAsync(image).ConfigureAwait(false);
                            signatures[image] = known;
                        }

                        (signed, detail) = known;
                    }
                }

                entries.Add(new AutostartEntry(
                    candidate.Category, candidate.Location, candidate.Entry, candidate.Enabled, candidate.Profile, candidate.Description,
                    candidate.Image, candidate.LaunchString, candidate.Script, signed, detail, missing, writable,
                    findings.Distinct(StringComparer.Ordinal).ToList()));
            }

            var kept = entries
                .Where(e => !query.UnsignedOnly || e.Signed == false || (e.Signed is null && e.SignatureDetail is not null) ||
                            e.ImageMissing || e.WritableByOthers)
                .OrderBy(e => Array.IndexOf(Categories, e.Category))
                .ThenBy(e => e.Entry, StringComparer.Ordinal)
                .ThenBy(e => e.Location, StringComparer.Ordinal)
                .ToList();

            _limitations.Add(AclNote);
            if (_unreadable.Count > 0)
            {
                _limitations.Add(_unreadable.Count <= 5
                    ? $"Could not read: {string.Join("; ", _unreadable)}."
                    : $"{_unreadable.Count} files could not be read, among them: {string.Join("; ", _unreadable.Take(5))}.");
            }

            var rows = kept.Take(owner.Options.MaxResults).ToList();
            return new AutostartAuditResult(
                rows, kept.Count, kept.Count > rows.Count, elevated, verify,
                kept.Count(e => e.Signed == false), kept.Count(e => e.ImageMissing), kept.Count(e => e.WritableByOthers), _limitations);
        }

        private async Task LaunchdAsync(
            string category, IEnumerable<string> directories, string? overrideDomain, string? profile, IReadOnlySet<int> sourceOwners,
            Func<PlistDictionary, Task<IReadOnlySet<int>?>> imageOwners)
        {
            var overrides = overrideDomain is null ? null : await OverridesAsync(overrideDomain).ConfigureAwait(false);

            // The sealed volume is Apple's and cannot be written to: with hideApple there is nothing to read there.
            var plists = directories.SelectMany(List)
                .Where(p => p.EndsWith(".plist", StringComparison.Ordinal))
                .Where(p => !(query.HideApple && p.StartsWith(SealedVolume, StringComparison.Ordinal)))
                .ToList();
            var readable = await RegularFilesAsync(plists).ConfigureAwait(false);
            foreach (var plistPath in plists)
            {
                var name = plistPath[(plistPath.LastIndexOf('/') + 1)..^".plist".Length];
                if (!readable.TryGetValue(plistPath, out var read))
                {
                    continue; // gone between the listing and the stat
                }

                if (read.Problem is not null)
                {
                    // A FIFO, a device or a link to one would hang or flood plutil, which runs as root: never read, always shown.
                    _found.Add(new Candidate(category, plistPath, name, true, profile, null, null, null, null, sourceOwners, sourceOwners,
                        Problem: read.Problem));
                    continue;
                }

                if (await ReadPlistAsync(read.Path!).ConfigureAwait(false) is not { } plist)
                {
                    continue;
                }

                var label = plist.String("Label") ?? name;
                var arguments = plist.Strings("ProgramArguments");
                var program = plist.String("Program") ?? arguments.FirstOrDefault();
                var disabled = overrides is not null && overrides.TryGetValue(label, out var off) ? off : plist.Bool("Disabled") ?? false;
                _found.Add(new Candidate(
                    category, plistPath, label, !disabled, profile, Triggers(plist), program,
                    arguments.Count > 0 ? string.Join(' ', arguments) : program, ScriptOf(program, arguments.Skip(1)),
                    sourceOwners, await imageOwners(plist).ConfigureAwait(false)));
            }
        }

        /// <summary>For each path: the regular file to read (itself, or what its link leads to), or why it must not be read.</summary>
        /// <remarks>Absent paths have no entry. Names with a control character are never statted.</remarks>
        private async Task<Dictionary<string, (string? Path, string? Problem)>> RegularFilesAsync(IReadOnlyList<string> paths)
        {
            var result = new Dictionary<string, (string? Path, string? Problem)>(StringComparer.Ordinal);
            foreach (var path in paths.Where(StatLines.HasControlCharacter))
            {
                result[path] = (null, "its name contains a control character");
            }

            var stats = await StatBatchesAsync(paths).ConfigureAwait(false);
            var links = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var (path, line) in stats)
            {
                if (line.Kind == StatKind.File)
                {
                    result[path] = (path, null);
                }
                else if (line.Kind != StatKind.Link)
                {
                    result[path] = (null, $"it is not a regular file ({KindName(line.Kind)}), so it was not read");
                }
                else
                {
                    try
                    {
                        links[path] = owner.Resolve(path);
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        result[path] = (null, $"it is a link that cannot be followed ({ex.Message})");
                    }
                }
            }

            var targets = await StatBatchesAsync(links.Values).ConfigureAwait(false);
            foreach (var (path, target) in links)
            {
                result[path] = targets.TryGetValue(target, out var line) && line.Kind == StatKind.File
                    ? (target, null)
                    : (null, $"it is a link to {Printable(target)}, which is not a regular file, so it was not read");
            }

            return result;
        }

        /// <summary>stat for every path; what stat was refused is remembered, so it is never reported as absent.</summary>
        private async Task<IReadOnlyDictionary<string, StatLine>> StatBatchesAsync(IEnumerable<string> paths)
        {
            var outcome = await StatLines.StatOutcomeAsync(Commands, paths, Timeout, cancellationToken).ConfigureAwait(false);
            _denied.UnionWith(outcome.Denied);
            return outcome.Lines;
        }

        /// <summary>Whether periodic(8) would run it: a regular file with an execute bit, after following a link.</summary>
        private bool Executable(string path, IReadOnlyDictionary<string, StatLine> stats)
        {
            if (!stats.TryGetValue(path, out var line))
            {
                return false;
            }

            if (line.Kind == StatKind.Link)
            {
                var target = Spellings(path).Skip(1).FirstOrDefault();
                if (target is null || !stats.TryGetValue(target, out line))
                {
                    return false;
                }
            }

            return line.Kind == StatKind.File && (line.Mode & AnyExecuteBit) != 0;
        }

        private static string KindName(StatKind kind) => kind switch
        {
            StatKind.Fifo => "a FIFO",
            StatKind.Socket => "a socket",
            StatKind.CharacterDevice or StatKind.BlockDevice => "a device",
            StatKind.Directory => "a directory",
            _ => "not a file",
        };

        private void AddCron(string location, CronLine job, string? profile, IReadOnlySet<int> sourceOwners, IReadOnlySet<int> imageOwners)
        {
            var words = job.Command.Split(' ');
            var image = words[0].StartsWith('/') ? words[0] : null;
            _found.Add(new Candidate("cron", location, job.Command, true, profile, job.Schedule, image, job.Command, ScriptOf(image, words.Skip(1)),
                sourceOwners, imageOwners));
        }

        private bool Matches(Candidate candidate) =>
            string.IsNullOrWhiteSpace(query.NameFilter) ||
            new[] { candidate.Entry, candidate.Image, candidate.Location, candidate.Description, candidate.LaunchString }
                .Any(v => v?.Contains(query.NameFilter, StringComparison.OrdinalIgnoreCase) == true);

        /// <summary>Whether another account could change what this entry runs; each reason goes into findings.</summary>
        private bool Judge(Candidate candidate, IReadOnlyDictionary<string, StatLine> stats, List<string> findings, out bool missing)
        {
            missing = false;
            var notes = new List<string>(); // reported, but not a way for another account in
            if (candidate.Problem is { } problem)
            {
                findings.Add($"{Printable(candidate.Location)}: {problem}; it was not examined.");
                return true;
            }

            JudgePath(candidate.Location, candidate.SourceOwners, stats, findings);
            foreach (var target in new[] { candidate.Image, candidate.Script }.OfType<string>())
            {
                if (!target.StartsWith('/'))
                {
                    continue;
                }

                if (StatLines.HasControlCharacter(target))
                {
                    findings.Add($"{Printable(target)}: its name contains a control character; it was not examined.");
                    continue;
                }

                if (_denied.Contains(target))
                {
                    // Out of this server's sight is not absent: a program in a home it may not search is still there.
                    notes.Add($"{target} could not be examined (permission denied).");
                    continue;
                }

                if (!stats.ContainsKey(target))
                {
                    missing = true;
                    notes.Add($"{target} does not exist.");
                    continue;
                }

                JudgePath(target, candidate.ImageOwners, stats, findings);
            }

            var writable = findings.Count > 0;
            findings.AddRange(notes);
            return writable;
        }

        private void JudgePath(string path, IReadOnlySet<int>? owners, IReadOnlyDictionary<string, StatLine> stats, List<string> findings)
        {
            // A location can be a command ("kmutil showloaded") rather than a file; there is nothing to stat.
            if (!path.StartsWith('/'))
            {
                return;
            }

            foreach (var each in Spellings(path).SelectMany(StartupPermissions.Chain).Distinct(StringComparer.Ordinal))
            {
                if (!stats.TryGetValue(each, out var line))
                {
                    continue; // an absent directory above an existing file is a spelling, not a finding
                }

                // Root may own anything; null owners means any account may own the file and the directories above it.
                var allowed = owners is null ? new HashSet<int> { line.Uid } : new HashSet<int>(owners) { 0 };
                if (!StatLines.WritableByOthers(line, allowed))
                {
                    continue;
                }

                findings.Add(!allowed.Contains(line.Uid)
                    ? $"{each} is owned by uid {line.Uid}, not {Describe(allowed)}."
                    : $"{each} is writable by {((line.Mode & 0b000_000_010) != 0 ? "everyone" : $"group {line.Gid}")} (mode {Convert.ToString(line.Mode, 8).PadLeft(4, '0')}).");
            }
        }

        private IEnumerable<string> Spellings(string path)
        {
            yield return path;
            string resolved;
            try
            {
                resolved = owner.Resolve(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                yield break; // a link this server may not follow: the spelling as given is still judged
            }

            if (resolved != path)
            {
                yield return resolved;
            }
        }

        private async Task<IReadOnlyDictionary<string, StatLine>> StatAllAsync(IReadOnlyList<Candidate> candidates)
        {
            var paths = candidates
                .Where(c => c.Problem is null)
                .SelectMany(c => new[] { c.Location, c.Image, c.Script })
                .OfType<string>()
                .Where(p => p.StartsWith('/') && !StatLines.HasControlCharacter(p))
                .SelectMany(Spellings)
                .SelectMany(StartupPermissions.Chain)
                .Distinct(StringComparer.Ordinal)
                .ToList();

            return await StatBatchesAsync(paths).ConfigureAwait(false);
        }

        private async Task<(bool? Signed, string Detail)> SignatureAsync(string image)
        {
            ExternalResult verify, display;
            try
            {
                verify = await Commands.RunAsync("codesign", ["--verify", "--strict", "--", image], Timeout, cancellationToken).ConfigureAwait(false);
                display = verify.ExitCode == 0
                    ? await Commands.RunAsync("codesign", ["-dvvv", "--", image], Timeout, cancellationToken).ConfigureAwait(false)
                    : verify;
            }
            catch (ExternalCommandException ex)
            {
                // Not judged is neither unsigned nor signed: unsignedOnly keeps it, so somebody looks at it.
                return (null, $"codesign did not finish: {ex.Message}");
            }

            if (verify.ExitCode != 0)
            {
                var reason = verify.StandardError.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0) ?? $"codesign exit {verify.ExitCode}";
                return (false, reason.StartsWith(image + ": ", StringComparison.Ordinal) ? reason[(image.Length + 2)..] : reason);
            }

            var details = CodesignDisplay.Details(display.StandardError);
            return (true, details.SignedByApple ? "Signed by Apple" : details.Authorities.FirstOrDefault() ?? "Signed");
        }

        private async Task<PlistDictionary?> ReadPlistAsync(string path)
        {
            try
            {
                return await Plutil.ReadAsync(Commands, path, Timeout, cancellationToken).ConfigureAwait(false);
            }
            catch (ServiceQueryException ex)
            {
                _unreadable.Add(ex.Message);
                return null;
            }
            catch (ExternalCommandException ex)
            {
                _unreadable.Add($"plutil did not finish on {path}: {ex.Message}");
                return null;
            }
        }

        private async Task<IReadOnlyDictionary<string, bool>?> OverridesAsync(string domain)
        {
            if (!_overrides.TryGetValue(domain, out var known))
            {
                var result = await Commands.RunAsync("launchctl", ["print-disabled", domain], Timeout, cancellationToken).ConfigureAwait(false);
                known = result.ExitCode == 0 ? LaunchctlDisabled.Parse(result.StandardOutput) : new Dictionary<string, bool>();
                _overrides[domain] = known;
            }

            return known;
        }

        private async Task<int?> UidAsync(string user)
        {
            if (!_uids.TryGetValue(user, out var uid))
            {
                var result = StatLines.HasControlCharacter(user) ? null
                    : await Commands.RunAsync("id", ["-u", "--", user], Timeout, cancellationToken).ConfigureAwait(false);
                uid = result is { ExitCode: 0 } && int.TryParse(result.StandardOutput.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var value)
                    ? value
                    : null;
                _uids[user] = uid;
            }

            return uid;
        }

        private async Task<int?> ConsoleUserAsync()
        {
            var result = await Commands.RunAsync("stat", ["-f", "%u", "/dev/console"], Timeout, cancellationToken).ConfigureAwait(false);
            return result.ExitCode == 0 && int.TryParse(result.StandardOutput.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var uid) ? uid : null;
        }

        private async Task<IReadOnlyDictionary<string, StatLine>> HomesAsync() =>
            _homes ??= new Dictionary<string, StatLine>(
                await StatLines.StatAsync(Commands, owner.ListHomes(), Timeout, cancellationToken).ConfigureAwait(false),
                StringComparer.Ordinal);

        private IEnumerable<string> List(string directory)
        {
            try
            {
                return owner.ListEntries(directory).Order(StringComparer.Ordinal).ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _limitations.Add($"Could not list {directory}: {ex.Message}");
                return [];
            }
        }

        private string? Read(string path)
        {
            try
            {
                return owner.ReadText(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _unreadable.Add($"{path}: {ex.Message}");
                return null;
            }
        }
    }

    /// <summary>When launchd starts the job, in words.</summary>
    private static string Triggers(PlistDictionary plist)
    {
        var triggers = new List<string>();
        if (plist.Bool("RunAtLoad") == true) triggers.Add("at load");
        if (plist.Bool("KeepAlive") == true || plist.Dict("KeepAlive") is not null) triggers.Add("kept alive");
        if (plist.Integer("StartInterval") is { } seconds) triggers.Add($"every {seconds} s");
        if (plist.ContainsKey("StartCalendarInterval")) triggers.Add("on a calendar schedule");
        if (plist.ContainsKey("WatchPaths") || plist.ContainsKey("QueueDirectories")) triggers.Add("when a watched path changes");
        if (plist.ContainsKey("Sockets") || plist.ContainsKey("MachServices")) triggers.Add("on demand, when its socket or service is used");
        return triggers.Count == 0 ? "only when started by hand or by another job" : string.Join(", ", triggers);
    }

    /// <summary>The script an interpreter runs: the first rooted argument after it.</summary>
    private static string? ScriptOf(string? program, IEnumerable<string> arguments) =>
        program is not null && Interpreters.Contains(program, StringComparer.Ordinal)
            ? arguments.FirstOrDefault(a => a.StartsWith('/'))?.Split(' ')[0]
            : null;

    private static string Describe(IReadOnlySet<int> owners) =>
        owners.Count == 1 && owners.Contains(0) ? "root" : "uid " + string.Join(" or ", owners.Order());

    private static string Printable(string text) => string.Concat(text.Select(c => char.IsControl(c) ? '?' : c));

    private static IEnumerable<string> DefaultHomes()
    {
        try
        {
            return Directory.EnumerateDirectories("/Users")
                .Where(d => Path.GetFileName(d) is { Length: > 0 } name && name != "Shared" && !name.StartsWith('.'))
                .Select(d => "/Users/" + Path.GetFileName(d))
                .ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static IEnumerable<string> DefaultEntries(string directory) =>
        Directory.Exists(directory) ? Directory.EnumerateFileSystemEntries(directory).ToList() : [];
}
