using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DiagRelay.Mcp;

/// <summary>One target to pre-connect at launch: its alias, address, token and optional port.</summary>
internal sealed record RelayTargetEntry(string? As, string Target, string Token, int? Port);

/// <summary>
/// Reads and updates the targets file the relay pre-connects from at launch.
/// </summary>
/// <remarks>
/// <para>The relay's tool list is dynamic, but this client fixes the callable tool set when it first
/// enumerates the server -- a target connected later, mid-session, is not picked up until a reload, and
/// a reload restarts the relay and drops the connection. So targets listed here are connected <em>before</em>
/// the stdio host starts answering, which puts each target's <c>alias__tool</c> tools in the very first
/// <c>tools/list</c>. Changing the fleet is an edit to this file plus a fresh session, never a change to
/// the MCP registration -- the addresses still live in data, not configuration.</para>
/// <para>One shape, one path: a JSON object with a <c>targets</c> array at
/// <c>%USERPROFILE%\.windiag-targets.json</c>.</para>
/// <para><strong>Every relay process shares this one file.</strong> Each Claude Code session spawns its
/// own relay, and each <c>connect</c> rewrites the file, so reads and writes are serialised on a named
/// cross-process mutex and every write lands atomically through a temporary file. Without both, two
/// sessions connecting at once silently lose one another's target -- and the file holds every target's
/// bearer token, so a write torn by process death would destroy all of them.</para>
/// </remarks>
internal static class RelayTargetsFile
{
    public const string FileName = ".windiag-targets.json";

    /// <summary>Kept beside the file by every atomic write, so a torn or corrupted file has a fallback.</summary>
    private const string BackupSuffix = ".bak";

    /// <summary>The sibling file Unix relays lock; it holds nothing, and a leftover one is harmless.</summary>
    internal const string LockSuffix = ".lock";

    /// <summary>Owner read and write, nothing else: the Unix equivalent of the Windows ACL (0600).</summary>
    internal const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    /// <summary>Generous: the critical section is one small read and one rename, never a network call.</summary>
    private static readonly TimeSpan LockTimeout = TimeSpan.FromSeconds(10);

    /// <summary>The single path the relay looks for the targets file at.</summary>
    public static string DefaultPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), FileName);

    /// <summary>Loads and validates the targets file, or null when it does not exist.</summary>
    /// <exception cref="RelayException">The file exists but is not valid, so the caller can log it.</exception>
    public static IReadOnlyList<RelayTargetEntry>? Load(string path)
    {
        using var guard = Lock(path);
        return LoadLocked(path);
    }

    /// <summary>
    /// Adds or replaces one target in the file, keeping every other entry, so a target connected at
    /// runtime survives a relay restart and is pre-connected next launch.
    /// </summary>
    /// <remarks>
    /// A matching alias is replaced (a repoint), otherwise the target is appended. Read and write happen
    /// under one lock, so a concurrent relay cannot interleave and drop this entry. The file is parsed
    /// before being rewritten, so a malformed file is refused rather than overwritten with a half-file
    /// that would lose whatever it already held.
    /// </remarks>
    public static void Upsert(string path, RelayTargetEntry entry)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(entry.As);

        using var guard = Lock(path);

        var entries = LoadLocked(path) is { } existing
            ? new List<RelayTargetEntry>(existing)
            : new List<RelayTargetEntry>();

        // Matched on the EFFECTIVE alias: an entry written by hand without an "as" still occupies the
        // alias derived from its address, so comparing the raw field would append a twin that races the
        // original on every launch instead of repointing it.
        var index = entries.FindIndex(
            e => string.Equals(EffectiveAlias(e), entry.As, StringComparison.OrdinalIgnoreCase));

        if (index >= 0)
        {
            entries[index] = entry;
        }
        else
        {
            entries.Add(entry);
        }

        WriteAtomic(path, Serialize(entries));
    }

    /// <summary>The alias an entry occupies: its own, or the one derived from its address.</summary>
    public static string EffectiveAlias(RelayTargetEntry entry) =>
        string.IsNullOrWhiteSpace(entry.As)
            ? RelayState.DefaultAlias(RelayState.BuildAddress(entry.Target, entry.Port))
            : entry.As.Trim();

    /// <summary>Parses the targets-file JSON, validating that every entry has a target and a token.</summary>
    public static IReadOnlyList<RelayTargetEntry> Parse(string json)
    {
        RelayTargetsDocument? document;
        try
        {
            document = JsonSerializer.Deserialize<RelayTargetsDocument>(json, JsonOptions);
        }
        catch (JsonException ex)
        {
            throw new RelayException($"the targets file is not valid JSON: {ex.Message}", ex);
        }

        if (document?.Targets is not { } targets)
        {
            throw new RelayException(
                "the targets file must be a JSON object with a \"targets\" array, for example " +
                "{\"targets\":[{\"as\":\"w11\",\"target\":\"192.168.32.93\",\"token\":\"...\"}]}.");
        }

        var result = new List<RelayTargetEntry>(targets.Count);
        for (var i = 0; i < targets.Count; i++)
        {
            var entry = targets[i];
            if (string.IsNullOrWhiteSpace(entry.Target) || string.IsNullOrWhiteSpace(entry.Token))
            {
                throw new RelayException($"targets[{i}] needs both a \"target\" and a \"token\".");
            }

            result.Add(new RelayTargetEntry(
                As: string.IsNullOrWhiteSpace(entry.As) ? null : entry.As.Trim(),
                Target: entry.Target.Trim(),
                Token: entry.Token,
                Port: entry.Port));
        }

        return result;
    }

    /// <summary>Reads and parses the file, assuming the lock is already held.</summary>
    private static IReadOnlyList<RelayTargetEntry>? LoadLocked(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        var text = Read(path);

        // An empty file is not content worth preserving -- it is what a write torn by process death
        // leaves behind. Healing it here means the next connect rewrites it, instead of every future
        // connect refusing to touch a "malformed" file that has nothing left in it to fix.
        if (string.IsNullOrWhiteSpace(text))
        {
            return Restore(path);
        }

        try
        {
            return Parse(text);
        }
        catch (RelayException)
        {
            // A genuinely malformed file is never overwritten, but a backup from the last good write is
            // a better answer than refusing to start with any targets at all.
            var restored = Restore(path);
            if (restored is not null)
            {
                return restored;
            }

            throw;
        }
    }

    /// <summary>Reads the last good copy left by an atomic write, if there is one that parses.</summary>
    private static IReadOnlyList<RelayTargetEntry>? Restore(string path)
    {
        var backup = path + BackupSuffix;
        if (!File.Exists(backup))
        {
            return null;
        }

        try
        {
            var text = Read(backup);
            return string.IsNullOrWhiteSpace(text) ? null : Parse(text);
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>Reads a file, retrying briefly so an overlapping write is not reported as corruption.</summary>
    /// <remarks>
    /// The mutex serialises relays that use it, but a hand edit or an editor's own save can still hold
    /// the file for an instant, and Windows share-mode checks surface that as an IOException. Reporting
    /// it verbatim would print "ignoring the targets file" over a file that is perfectly fine.
    /// </remarks>
    private static string Read(string path)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                using var stream = new FileStream(
                    path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                return reader.ReadToEnd();
            }
            catch (IOException) when (attempt < 4)
            {
                Thread.Sleep(50);
            }
        }
    }

    /// <summary>
    /// Writes the file so it is never observed half-written: a temporary file is written and flushed,
    /// then swapped in, keeping the previous contents as a backup.
    /// </summary>
    private static void WriteAtomic(string path, string json)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temp = path + ".tmp";

        using (var stream = OpenTemp(temp))
        using (var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
        {
            writer.Write(json);
            writer.Flush();
            stream.Flush(flushToDisk: true);
        }

        // Restrict the temporary file BEFORE it becomes the real one, so the credentials it carries are
        // never briefly readable under the directory's inherited permissions.
        Restrict(temp);

        if (File.Exists(path))
        {
            // Atomic swap that also leaves the previous contents recoverable.
            File.Replace(temp, path, path + BackupSuffix, ignoreMetadataErrors: true);
        }
        else
        {
            File.Move(temp, path);
        }

        // Again on the destination, and on the backup: File.Replace keeps the DESTINATION's security
        // descriptor, so restricting only the temporary file silently achieves nothing for a file that
        // already existed -- which is every write after the first. Verified by reading the ACL back.
        Restrict(path);

        var backup = path + BackupSuffix;
        if (File.Exists(backup))
        {
            Restrict(backup);
        }
    }

    /// <summary>Opens the file the next write goes to, restricted from the moment it exists.</summary>
    /// <remarks>
    /// On Unix the file is created 0600 rather than tightened after the tokens are written into it --
    /// tightening afterwards leaves a window in which every token is world-readable. It is deleted first
    /// because FileMode.Create on an existing file keeps that file's mode, and UnixCreateMode applies only
    /// when a file is created, so a .tmp left behind by a crashed write would carry its old mode into this
    /// one. The delete cannot race another relay: callers hold the targets-file lock.
    /// </remarks>
    internal static FileStream OpenTemp(string temp)
    {
        if (OperatingSystem.IsWindows())
        {
            return new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None);
        }

        File.Delete(temp);
        return new FileStream(temp, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            UnixCreateMode = OwnerOnly,
        });
    }

    /// <summary>
    /// Restricts the file to the current user, because it stores every target's bearer token in clear.
    /// </summary>
    /// <remarks>
    /// Left to inherit, a file under the profile is typically readable by SYSTEM and every local
    /// administrator -- and on these targets a token is command execution at the server's privilege
    /// level. Best effort: a filesystem that cannot carry an ACL is a reason to warn, not to refuse to
    /// save the target the operator just connected.
    /// </remarks>
    private static void Restrict(string path)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                RestrictWithAcl(path);
            }
            else
            {
                File.SetUnixFileMode(path, OwnerOnly);
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or PlatformNotSupportedException
                                       or NotSupportedException or IOException or InvalidOperationException)
        {
            Console.Error.WriteLine(
                $"[windiag-relay] WARNING: could not restrict {path} to your account ({ex.Message}). " +
                "It holds bearer tokens in plain text -- tighten its permissions by hand.");
        }
    }

    /// <summary>The Windows half of <see cref="Restrict"/>: inheritance off, owner set, one ACE.</summary>
    [SupportedOSPlatform("windows")]
    private static void RestrictWithAcl(string path)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (identity.User is not { } user)
        {
            return;
        }

        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(user);
        security.AddAccessRule(new FileSystemAccessRule(
            user, FileSystemRights.FullControl, AccessControlType.Allow));

        new FileInfo(path).SetAccessControl(security);
    }

    /// <summary>Serialises entries back to the file's single shape.</summary>
    private static string Serialize(IReadOnlyList<RelayTargetEntry> entries)
    {
        var document = new RelayTargetsDocument
        {
            Targets = entries
                .Select(e => new RelayTargetEntryDto { As = e.As, Target = e.Target, Token = e.Token, Port = e.Port })
                .ToList()
        };

        return JsonSerializer.Serialize(document, WriteOptions);
    }

    /// <summary>Takes the cross-process lock that serialises every relay's access to this file.</summary>
    private static IDisposable Lock(string path) => Lock(path, LockTimeout);

    /// <remarks>
    /// A named mutex on Windows, where it is proven; an exclusive file lock everywhere else. .NET takes
    /// FileShare.None on Unix with flock, whose locks belong to open file descriptions -- so two opens
    /// conflict even inside one process, which lets an in-process test prove the cross-process
    /// behaviour -- and the kernel releases it when its holder dies, with no abandonment to handle.
    /// Setting DOTNET_SYSTEM_IO_DISABLEFILELOCKING turns that off and with it this lock; do not.
    /// </remarks>
    internal static IDisposable Lock(string path, TimeSpan timeout) =>
        OperatingSystem.IsWindows() ? LockWithMutex(path, timeout) : LockWithFile(path, timeout);

    private static IDisposable LockWithMutex(string path, TimeSpan timeout)
    {
        var mutex = CreateMutex(path);

        try
        {
            if (!mutex.WaitOne(timeout))
            {
                throw new RelayException(
                    $"another process has held the targets file lock for over {timeout.TotalSeconds:0}s. " +
                    "Retry, or check for a stuck relay process.");
            }
        }
        catch (AbandonedMutexException)
        {
            // The previous holder died mid-update, so ownership passes here. That is exactly the case the
            // atomic write and its backup exist to make recoverable; carry on and use the lock.
        }
        catch (Exception)
        {
            mutex.Dispose();
            throw;
        }

        return new Guard(mutex);
    }

    /// <summary>EWOULDBLOCK: the one way of failing to take the lock that is worth waiting out.</summary>
    /// <remarks>
    /// On Unix .NET reports a failed flock as an IOException whose HResult is the raw errno, and that is
    /// the only thing telling contention apart from a failure that cannot clear -- a symlink loop is an
    /// IOException too. Retrying every IOException waited out the whole timeout on those and then blamed
    /// another relay. The value is 11 on Linux (measured) and 35 on macOS and the BSDs, where it is the
    /// platform's documented EWOULDBLOCK and unverified until the macOS CI job runs.
    /// </remarks>
    private static int WouldBlock => OperatingSystem.IsLinux() ? 11 : 35;

    [UnsupportedOSPlatform("windows")]
    private static FileStream LockWithFile(string path, TimeSpan timeout)
    {
        var full = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(full);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var lockPath = full + LockSuffix;
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            try
            {
                // Owner-only from birth: .NET takes flock whatever the access mode, so a lock file any
                // local user could open read-only was one any local user could hold, stalling every
                // relay of the owner's at startup.
                var stream = new FileStream(lockPath, new FileStreamOptions
                {
                    Mode = FileMode.OpenOrCreate,
                    Access = FileAccess.ReadWrite,
                    Share = FileShare.None,
                    UnixCreateMode = OwnerOnly,
                });
                TightenLeftover(stream, lockPath);
                return stream;
            }
            catch (IOException ex) when (ex.HResult == WouldBlock && DateTime.UtcNow < deadline)
            {
                Thread.Sleep(25);
            }
            catch (IOException ex) when (ex.HResult == WouldBlock)
            {
                throw new RelayException(
                    $"another process has held the targets file lock for over {timeout.TotalSeconds:0}s. " +
                    "Retry, or check for a stuck relay process.", ex);
            }
            catch (IOException ex)
            {
                throw new RelayException($"could not take the targets file lock at {lockPath}: {ex.Message}", ex);
            }
        }
    }

    /// <summary>Restricts a lock file an older relay left behind; UnixCreateMode only applies to new ones.</summary>
    /// <remarks>
    /// Through the open handle rather than the path, so the file restricted is the one actually locked.
    /// Best effort, like <see cref="Restrict"/>: failing to tighten it leaves it readable, but the lock
    /// still works, and refusing to start would be the worse outcome.
    /// </remarks>
    [UnsupportedOSPlatform("windows")]
    private static void TightenLeftover(FileStream stream, string lockPath)
    {
        try
        {
            File.SetUnixFileMode(stream.SafeFileHandle, OwnerOnly);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            Console.Error.WriteLine(
                $"[windiag-relay] WARNING: could not restrict {lockPath} to your account ({ex.Message}).");
        }
    }

    private static Mutex CreateMutex(string path)
    {
        // Named for the file, so two different targets files never contend, and lower-cased because
        // Windows paths are case-insensitive while the mutex name is not.
        var key = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(path).ToLowerInvariant())))[..16];

        try
        {
            // Global so a relay under a different session still serialises against this one.
            return new Mutex(initiallyOwned: false, $"Global\\windiag-targets-{key}");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or NotSupportedException)
        {
            return new Mutex(initiallyOwned: false, $"Local\\windiag-targets-{key}");
        }
    }

    private sealed class Guard : IDisposable
    {
        private readonly Mutex _mutex;

        public Guard(Mutex mutex) => _mutex = mutex;

        public void Dispose()
        {
            try
            {
                _mutex.ReleaseMutex();
            }
            catch (ApplicationException)
            {
                // Not the owner (an abandoned-mutex path); nothing useful to do while tearing down.
            }

            _mutex.Dispose();
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private sealed class RelayTargetsDocument
    {
        public List<RelayTargetEntryDto>? Targets { get; set; }
    }

    private sealed class RelayTargetEntryDto
    {
        public string? As { get; set; }
        public string? Target { get; set; }
        public string? Token { get; set; }
        public int? Port { get; set; }
    }
}
