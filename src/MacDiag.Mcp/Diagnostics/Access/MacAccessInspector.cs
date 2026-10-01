using System.Globalization;
using System.Text.RegularExpressions;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics.Handles;
using MacDiag.Mcp.Hosting;
using MacDiag.Mcp.Mac;
using MacDiag.Mcp.Mac.Parsers;

namespace MacDiag.Mcp.Diagnostics.Access;

/// <summary>Whether an account can read, write and execute a path: the kernel's own answer, and what explains it.</summary>
/// <remarks>
/// <para>The decision is access(2) itself, through /bin/test run as the subject -- sudo -n -u #uid when the server is
/// root. macOS ACLs (deny before allow, inheritance, nested groups, "everyone") and file flags are what the kernel
/// implements; re-deriving them here would be a second answer that can disagree with the first. A server that is
/// not root cannot ask on another account's behalf, and then says so: answering with its own rights would report
/// the server's access as the subject's.</para>
/// <para>test gets no "--": BSD test has none, so "test -r -- /p" is a three-argument expression that exits 2.
/// The two-argument form is unary whatever the operand is, and the path is always absolute. Any exit but 0 or 1,
/// or a sudo failure, is "not evaluated" -- never "denied".</para>
/// </remarks>
public sealed partial class MacAccessInspector(IExternalCommand commands, MacDiagOptions options) : IAccessInspector
{
    internal const string ProtectionNote =
        "System Integrity Protection and privacy (TCC) rules are not evaluated: a protected path can be refused to root even when this says allowed.";

    internal Func<string, string> Resolve { get; init; } = StartupPermissions.RealPath;

    internal IReadOnlyList<string>? Firmlinks { get; init; }

    public async Task<EffectiveAccessReport> InspectAsync(string path, string? account, int? processId, CancellationToken cancellationToken)
    {
        if ((account is null) == (processId is null))
        {
            throw new ArgumentException("Give exactly one of account (a user name or uid) or processId.");
        }

        if (string.IsNullOrEmpty(path) || StatLines.HasControlCharacter(path) || MacPaths.Lexical(path) is not { } full)
        {
            throw new ArgumentException($"'{path}' is not a full path; give one starting with '/'.", nameof(path));
        }

        if (account is not null && !AccountName().IsMatch(account))
        {
            throw new ArgumentException($"'{account}' is not a user name or numeric uid.", nameof(account));
        }

        var notes = new List<string>();
        var serverUid = await ServerUidAsync(cancellationToken).ConfigureAwait(false);
        var (subject, groupIds) = await SubjectAsync(account, processId, notes, cancellationToken).ConfigureAwait(false);

        string real;
        try
        {
            real = Resolve(full);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new AccessInspectionException($"Could not resolve {full}: {ex.Message}", ex);
        }

        var stats = await StatLines.StatAsync(commands, [real], options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        if (!stats.TryGetValue(real, out var stat))
        {
            throw new AccessInspectionException($"{real} does not exist, or this server cannot see it.");
        }

        var ownerName = await OneLineAsync("stat", ["-f", "%Su", "--", real], cancellationToken).ConfigureAwait(false) ?? stat.Uid.ToString(CultureInfo.InvariantCulture);
        var groupName = await OneLineAsync("stat", ["-f", "%Sg", "--", real], cancellationToken).ConfigureAwait(false) ?? stat.Gid.ToString(CultureInfo.InvariantCulture);
        var acl = LsAcl.Parse((await commands.RunAsync("ls", ["-lde", "--", real], options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false)).StandardOutput);
        var mount = await MountAsync(real, cancellationToken).ConfigureAwait(false);

        async Task<AccessDecision> Ask(string flag, string target)
        {
            var (allowed, why) = await TestAsync(subject.UserId, serverUid, flag, target, cancellationToken).ConfigureAwait(false);
            return new AccessDecision(allowed, why ?? $"the kernel's own check (access(2)) for {subject.Description}");
        }

        var read = await Ask("-r", real).ConfigureAwait(false);
        var write = await Ask("-w", real).ConfigureAwait(false);
        var execute = await Ask("-x", real).ConfigureAwait(false);

        var traversal = new List<PathStep>();
        foreach (var directory in StartupPermissions.Chain(real).SkipLast(1))
        {
            var search = await Ask("-x", directory).ConfigureAwait(false);
            traversal.Add(new PathStep(directory, search.Allowed,
                search.Allowed switch { true => "searchable", false => $"{subject.Description} cannot search it", null => search.Reason }));
        }

        var same = subject.UserId == serverUid;
        var probe = same
            ? new ServerProbe(serverUid, read.Allowed, write.Allowed, execute.Allowed, true)
            : new ServerProbe(
                serverUid,
                (await TestAsync(serverUid, serverUid, "-r", real, cancellationToken).ConfigureAwait(false)).Allowed,
                (await TestAsync(serverUid, serverUid, "-w", real, cancellationToken).ConfigureAwait(false)).Allowed,
                (await TestAsync(serverUid, serverUid, "-x", real, cancellationToken).ConfigureAwait(false)).Allowed,
                false);

        var denying = await DenyingEntriesAsync(acl, subject, groupIds, cancellationToken).ConfigureAwait(false);
        Explain(stat, denying, subject, mount, notes);
        return new EffectiveAccessReport(
            full, real == full ? null : real, Kind(stat.Kind), ownerName, groupName, Mode(stat.Mode), acl, stat.Flags,
            mount?.MountPoint, mount is null ? [] : [mount.FileSystem, .. mount.Options], subject, read, write, execute, traversal,
            traversal.FirstOrDefault(s => s.CanSearch == false)?.Path, probe, notes);
    }

    /// <summary>/bin/test as the subject: (true, null) allowed, (false, null) denied, (null, why) not evaluated.</summary>
    private async Task<(bool? Allowed, string? Why)> TestAsync(uint subject, uint server, string flag, string path, CancellationToken cancellationToken)
    {
        ExternalResult result;
        if (subject == server)
        {
            result = await commands.RunAsync("test", [flag, path], options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        }
        else if (server == 0)
        {
            result = await commands.RunAsync("sudo", ["-n", "-u", $"#{subject}", "/bin/test", flag, path], options.ExternalToolTimeout, cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            return (null, "not evaluated: asking on behalf of another account needs root");
        }

        // sudo's own refusals (a password needed, an unknown uid) also exit 1; they start with "sudo:".
        var stderr = result.StandardError.Trim();
        return result.ExitCode switch
        {
            0 => (true, null),
            1 when !stderr.StartsWith("sudo:", StringComparison.Ordinal) => (false, null),
            _ => (null, $"not evaluated: {(stderr.Length > 0 ? stderr.Split('\n')[0] : $"exit {result.ExitCode}")}"),
        };
    }

    private async Task<(AccessSubject Subject, IReadOnlySet<uint> GroupIds)> SubjectAsync(
        string? account, int? processId, List<string> notes, CancellationToken cancellationToken)
    {
        uint uid;
        string description;
        if (processId is { } pid)
        {
            var owner = await OneLineAsync("ps", ["-p", pid.ToString(CultureInfo.InvariantCulture), "-o", "uid="], cancellationToken).ConfigureAwait(false);
            if (!uint.TryParse(owner, NumberStyles.None, CultureInfo.InvariantCulture, out uid))
            {
                throw new AccessInspectionException($"No process with PID {pid} is running.");
            }

            description = $"process {pid}";
            notes.Add($"Process {pid} is evaluated as its user (uid {uid}), with that account's groups.");
        }
        else if (uint.TryParse(account, NumberStyles.None, CultureInfo.InvariantCulture, out uid))
        {
            description = $"uid {uid}";
        }
        else
        {
            var found = await OneLineAsync("id", ["-u", "--", account!], cancellationToken).ConfigureAwait(false);
            if (!uint.TryParse(found, NumberStyles.None, CultureInfo.InvariantCulture, out uid))
            {
                throw new AccessInspectionException($"There is no account named '{account}'.");
            }

            description = account!;
        }

        var key = uid.ToString(CultureInfo.InvariantCulture);
        var name = await OneLineAsync("id", ["-un", "--", key], cancellationToken).ConfigureAwait(false);
        // id -Gn joins names with spaces, and a directory group may hold one ("Domain Users"): the names are split only
        // when there are as many as there are gids, and the gids -- never the names -- decide whether an ACL applies.
        var ids = (await OneLineAsync("id", ["-G", "--", key], cancellationToken).ConfigureAwait(false) ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Select(g => uint.TryParse(g, NumberStyles.None, CultureInfo.InvariantCulture, out var gid) ? gid : (uint?)null)
            .OfType<uint>()
            .ToHashSet();
        var names = await OneLineAsync("id", ["-Gn", "--", key], cancellationToken).ConfigureAwait(false) ?? string.Empty;
        var split = names.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        IReadOnlyList<string> groups = split.Length == ids.Count || names.Length == 0 ? split : [names];
        if (processId is null && name is not null && description != name)
        {
            description = $"{name} (uid {uid})";
        }

        return (new AccessSubject(description, uid, name, groups), ids);
    }

    private async Task<uint> ServerUidAsync(CancellationToken cancellationToken) =>
        uint.TryParse(await OneLineAsync("id", ["-u"], cancellationToken).ConfigureAwait(false), NumberStyles.None, CultureInfo.InvariantCulture, out var uid)
            ? uid
            : throw new AccessInspectionException("Could not learn this server's own uid from id -u.");

    /// <summary>The mount the path is on: the longest whole-component prefix of any of its spellings.</summary>
    /// <remarks>Firmlinks are not links: /Users/a/f keeps its spelling, and only its /System/Volumes/Data form
    /// matches the data volume -- matched as spelled, every user path would be on the sealed, read-only root.</remarks>
    private async Task<MacMount?> MountAsync(string path, CancellationToken cancellationToken)
    {
        var result = await commands.RunAsync("mount", [], options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        var mounts = result.ExitCode == 0 ? MountList.Parse(result.StandardOutput) : [];
        var spellings = PathSpellings.Of(path, Firmlinks ?? PathSpellings.SystemFirmlinks);
        return mounts
            .Where(m => spellings.Any(s => Under(s, m.MountPoint)))
            .OrderByDescending(m => m.MountPoint.Length)
            .FirstOrDefault();
    }

    private static bool Under(string path, string directory) =>
        directory == "/" || path == directory || path.StartsWith(directory + "/", StringComparison.Ordinal);

    /// <summary>The deny entries that name the subject: its user, everyone, or a group it is in, matched by gid.</summary>
    private async Task<IReadOnlyList<(string Principal, string Entry)>> DenyingEntriesAsync(
        IReadOnlyList<string> acl, AccessSubject subject, IReadOnlySet<uint> groupIds, CancellationToken cancellationToken)
    {
        var denying = new List<(string, string)>();
        foreach (var entry in acl)
        {
            var deny = entry.IndexOf(" deny ", StringComparison.Ordinal);
            if (deny <= 0)
            {
                continue;
            }

            var principal = entry[..deny];
            var applies = principal == "group:everyone"
                || (principal.StartsWith("user:", StringComparison.Ordinal) && principal["user:".Length..] == subject.UserName)
                || (principal.StartsWith("group:", StringComparison.Ordinal) &&
                    await GroupIdAsync(principal["group:".Length..], cancellationToken).ConfigureAwait(false) is { } gid && groupIds.Contains(gid));
            if (applies)
            {
                denying.Add((principal, entry));
            }
        }

        return denying;
    }

    /// <summary>A group's gid from the directory services cache, which knows directory groups as well as local ones.</summary>
    private async Task<uint?> GroupIdAsync(string group, CancellationToken cancellationToken)
    {
        if (StatLines.HasControlCharacter(group))
        {
            return null;
        }

        var result = await commands.RunAsync("dscacheutil", ["-q", "group", "-a", "name", group], options.ExternalToolTimeout, cancellationToken)
            .ConfigureAwait(false);
        var line = result.StandardOutput.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.StartsWith("gid: ", StringComparison.Ordinal));
        return line is not null && uint.TryParse(line["gid: ".Length..], NumberStyles.None, CultureInfo.InvariantCulture, out var gid) ? gid : null;
    }

    private static void Explain(
        StatLine stat, IReadOnlyList<(string Principal, string Entry)> denying, AccessSubject subject, MacMount? mount, List<string> notes)
    {
        if (stat.Flags.Contains("uchg") || stat.Flags.Contains("schg"))
        {
            notes.Add("It is immutable (uchg/schg): nobody can write, rename or delete it, root included, until the flag is cleared.");
        }

        if (stat.Flags.Contains("uappnd") || stat.Flags.Contains("sappnd"))
        {
            notes.Add("It is append-only (uappnd/sappnd): it can be added to but not rewritten.");
        }

        if (stat.Flags.Contains("restricted"))
        {
            notes.Add("System Integrity Protection protects it (restricted): root cannot change it while SIP is on.");
        }

        foreach (var (principal, entry) in denying)
        {
            notes.Add($"An ACL entry denies {subject.Description} through {principal}: '{entry}'. Deny entries are applied before allow entries.");
        }

        if (mount is { ReadOnly: true })
        {
            notes.Add($"It is on a read-only mount ({mount.MountPoint}): nobody can write it there.");
        }

        if (mount is not null && mount.Options.Contains("noexec") && stat.Kind == StatKind.File)
        {
            notes.Add($"It is on a noexec mount ({mount.MountPoint}): nothing on it can be executed.");
        }

        notes.Add(ProtectionNote);
    }

    private async Task<string?> OneLineAsync(string program, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        var result = await commands.RunAsync(program, arguments, options.ExternalToolTimeout, cancellationToken).ConfigureAwait(false);
        return result.ExitCode == 0 && result.StandardOutput.Trim() is { Length: > 0 } line ? line.Split('\n')[0].Trim() : null;
    }

    private static string Kind(StatKind kind) => kind switch
    {
        StatKind.Directory => "directory",
        StatKind.File => "file",
        StatKind.Link => "symbolic link",
        StatKind.Socket => "socket",
        StatKind.Fifo => "FIFO",
        StatKind.CharacterDevice => "character device",
        StatKind.BlockDevice => "block device",
        _ => "other",
    };

    private static string Mode(int mode)
    {
        var symbolic = new char[9];
        for (var i = 0; i < 9; i++)
        {
            symbolic[i] = (mode & (1 << (8 - i))) == 0 ? '-' : "rwx"[i % 3];
        }

        return $"{Convert.ToString(mode, 8).PadLeft(4, '0')} {new string(symbolic)}";
    }

    /// <summary>A short user name as macOS and directory services spell it, or a numeric uid; never an option or shell syntax.</summary>
    [GeneratedRegex(@"^(?:\d+|[A-Za-z_][A-Za-z0-9_.-]{0,254})\z")]
    private static partial Regex AccountName();
}
