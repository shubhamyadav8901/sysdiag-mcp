using System.Globalization;
using LinuxDiag.Mcp.Linux.Native;
using LinuxDiag.Mcp.Linux.Parsers;
using LinuxDiag.Mcp.Linux.Proc;

namespace LinuxDiag.Mcp.Diagnostics.Access;

public sealed class LinuxAccessInspector : IAccessInspector
{
    public EffectiveAccessReport Inspect(string path, string? account, int? processId)
    {
        try
        {
            return Evaluate(path, account, processId);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            // Without this the caller gets only "an error occurred": the kit passes through diagnostic exceptions alone.
            throw new AccessInspectionException(
                $"The server itself cannot read '{path}' or a directory above it ({ex.Message}), so access to it cannot be evaluated. " +
                "Run the server as root, or ask about a path it can reach.", ex);
        }
    }

    private static EffectiveAccessReport Evaluate(string path, string? account, int? processId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (string.IsNullOrWhiteSpace(account) == (processId is null))
        {
            throw new ArgumentException(
                "Name exactly one of account (a user name or numeric uid) or processId: access is always someone's.", nameof(account));
        }

        var full = Path.GetFullPath(path);
        var resolved = LibC.RealPath(full)
            ?? throw new ArgumentException($"'{full}' does not exist.", nameof(path));
        var notes = new List<string>();
        var subject = processId is { } pid ? ForProcess(pid, notes) : ForAccount(account!, notes);
        var mounts = MountInfo.Parse(ProcFiles.Read(MountInfo.SelfPath));
        var status = LibC.Status(resolved) ?? throw new ArgumentException($"'{full}' vanished while it was being read.", nameof(path));
        var facts = Facts(resolved, status, mounts);

        // Both the path as written and the path it resolves to must be walked: a link is read in its own directory.
        var traversal = Ancestors(full).Concat(Ancestors(resolved)).Distinct(StringComparer.Ordinal)
            .Select(directory =>
            {
                var directoryStatus = LibC.Status(directory);
                if (directoryStatus is null)
                {
                    return new PathStep(directory, false, "vanished while it was being read");
                }

                var (allowed, reason) = PosixAccess.Check(subject, Facts(directory, directoryStatus.Value, mounts), AccessRights.Execute);
                return new PathStep(directory, allowed, reason);
            })
            .ToList();
        var blocked = traversal.FirstOrDefault(s => !s.CanSearch);

        AccessDecision Decide(AccessRights right)
        {
            if (blocked is not null)
            {
                return new AccessDecision(false, $"cannot reach the file: no search permission on {blocked.Path} ({blocked.Reason})");
            }

            var (allowed, reason) = PosixAccess.Check(subject, facts, right);
            return new AccessDecision(allowed, reason);
        }

        var read = Decide(AccessRights.Read);
        var write = Decide(AccessRights.Write);
        var execute = Decide(AccessRights.Execute);
        var probe = Probe(resolved, subject);
        notes.AddRange(ProbeNotes(read, write, execute, probe));
        if (status.AppendOnly)
        {
            notes.Add("The file is append-only (chattr +a): a write must append; truncating or rewriting it fails, for root too.");
        }

        notes.Add("AppArmor and SELinux policy is not evaluated; the server's own kernel check reflects it only for the server's own credentials.");

        var mount = MountInfo.Containing(mounts, resolved);
        var defaultAcl = status.IsDirectory ? LibC.GetXattr(resolved, PosixAcl.DefaultAttribute) : null;
        var capabilities = status.IsRegular ? LibC.GetXattr(resolved, FileCapabilities.Attribute) : null;
        return new EffectiveAccessReport(
            full, resolved == full ? null : resolved,
            status.IsDirectory ? "directory" : status.IsRegular ? "regular file" : "special file",
            Account(status.UserId, LibC.UserById(status.UserId)?.Name), Account(status.GroupId, LibC.GroupName(status.GroupId)),
            $"{Convert.ToString(status.Mode & 0xFFF, 8).PadLeft(4, '0')} {PosixAcl.Rwx((status.Mode >> 6) & 7)}{PosixAcl.Rwx((status.Mode >> 3) & 7)}{PosixAcl.Rwx(status.Mode & 7)}",
            facts.Acl is null ? [] : Describe(facts.Acl),
            defaultAcl is null ? [] : Describe(PosixAcl.Parse(defaultAcl)),
            capabilities is null ? null : FileCapabilities.Describe(FileCapabilities.Parse(capabilities)),
            status.Immutable, status.AppendOnly, mount?.MountPoint, mount?.Options ?? [],
            subject, read, write, execute, traversal, blocked?.Path, probe, notes);
    }

    /// <summary>Where the evaluated subject is the server itself, the kernel's answer and the bits must agree; a difference names what else decides.</summary>
    internal static IEnumerable<string> ProbeNotes(AccessDecision read, AccessDecision write, AccessDecision execute, ServerProbe probe)
    {
        if (!probe.SameSubject)
        {
            yield break;
        }

        foreach (var (name, computed, kernel) in new[] { ("read", read.Allowed, probe.Read), ("write", write.Allowed, probe.Write), ("execute", execute.Allowed, probe.Execute) })
        {
            if (computed != kernel)
            {
                yield return $"The kernel {(kernel ? "allows" : "denies")} {name} for these credentials although mode, ACL and mount options say {(computed ? "allowed" : "denied")}: " +
                             "something else decides - an AppArmor or SELinux policy, a FUSE or network filesystem's own checks, or a user namespace.";
            }
        }
    }

    internal static IReadOnlyList<string> Ancestors(string path)
    {
        var chain = new List<string>();
        if (path == "/")
        {
            return chain;
        }

        for (var slash = path.LastIndexOf('/'); slash >= 0; slash = path.LastIndexOf('/', slash - 1))
        {
            chain.Add(slash == 0 ? "/" : path[..slash]);
            if (slash == 0)
            {
                break;
            }
        }

        chain.Reverse();
        return chain;
    }

    private static FileFacts Facts(string path, FileStatus status, IReadOnlyList<MountInfoEntry> mounts)
    {
        var acl = LibC.GetXattr(path, PosixAcl.AccessAttribute);
        var mount = MountInfo.Containing(mounts, path);
        return new FileFacts(
            status.UserId, status.GroupId, status.Mode & 0x1FF, status.IsDirectory, acl is null ? null : PosixAcl.Parse(acl),
            status.Immutable, status.AppendOnly, mount?.ReadOnly ?? false, mount?.NoExec ?? false, status.IsRegular);
    }

    private static AccessSubject ForAccount(string account, List<string> notes)
    {
        var numeric = uint.TryParse(account, NumberStyles.None, CultureInfo.InvariantCulture, out var uid);
        var entry = numeric ? LibC.UserById(uid) : LibC.UserByName(account);
        if (entry is null)
        {
            if (!numeric)
            {
                throw new ArgumentException($"There is no account named '{account}' on this machine.", nameof(account));
            }

            notes.Add($"uid {uid} has no account entry, so it was evaluated with no group memberships.");
            return new AccessSubject($"uid {uid}", uid, null, [], uid == 0, uid == 0);
        }

        notes.Add("Group memberships come from the account database. A process started before a membership change still has its old groups; pass processId to evaluate a running process.");
        if (entry.UserId == 0)
        {
            notes.Add("root is evaluated with CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH, as a root login has them; a confined service may not.");
        }

        return new AccessSubject(
            $"{entry.Name} (uid {entry.UserId})", entry.UserId, entry.Name, LibC.GroupsOf(entry.Name, entry.GroupId),
            entry.UserId == 0, entry.UserId == 0);
    }

    private static AccessSubject ForProcess(int processId, List<string> notes)
    {
        var pid = processId;
        var status = ProcFiles.ReadProcess(pid, "status") ?? throw new ArgumentException($"There is no process {pid}.", nameof(processId));
        var credentials = ProcCredentials.Parse(status);
        try
        {
            if (ProcFiles.ReadProcessLink(pid, "ns/mnt") is { } theirs && theirs != ProcFiles.ReadProcessLink(Environment.ProcessId, "ns/mnt"))
            {
                notes.Add($"Process {pid} is in another mount namespace - a container, or a service with a private /tmp - so it may see a different file at this path. The path was evaluated as the server sees it.");
            }
        }
        catch (UnauthorizedAccessException)
        {
            notes.Add($"Process {pid}'s mount namespace could not be read, so whether it sees the same file at this path is unknown.");
        }

        var name = LibC.UserById(credentials.FsUserId)?.Name;
        return new AccessSubject(
            $"process {pid} ({name ?? "uid"} {credentials.FsUserId})", credentials.FsUserId, name,
            credentials.Groups.Append(credentials.FsGroupId).Distinct().ToList(),
            credentials.Has(ProcCredentials.CapDacOverride), credentials.Has(ProcCredentials.CapDacReadSearch));
    }

    private static ServerProbe Probe(string path, AccessSubject subject)
    {
        var self = ProcCredentials.Parse(ProcFiles.Read("/proc/self/status"));
        var same = subject.UserId == self.FsUserId &&
                   subject.DacOverride == self.Has(ProcCredentials.CapDacOverride) &&
                   subject.DacReadSearch == self.Has(ProcCredentials.CapDacReadSearch) &&
                   subject.Groups.ToHashSet().SetEquals(self.Groups.Append(self.FsGroupId));
        return new ServerProbe(self.FsUserId, LibC.Access(path, LibC.ROk), LibC.Access(path, LibC.WOk), LibC.Access(path, LibC.XOk), same);
    }

    private static IReadOnlyList<string> Describe(IReadOnlyList<AclEntry> acl) =>
        PosixAcl.Describe(acl, uid => LibC.UserById(uid)?.Name, LibC.GroupName);

    private static string Account(uint id, string? name) =>
        name is null ? id.ToString(CultureInfo.InvariantCulture) : $"{name} ({id.ToString(CultureInfo.InvariantCulture)})";
}
