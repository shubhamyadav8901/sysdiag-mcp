using System.Diagnostics;
using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Diagnostics;
using LinuxDiag.Mcp.Diagnostics.Handles;
using LinuxDiag.Mcp.Diagnostics.Processes;
using LinuxDiag.Mcp.Tools;

namespace LinuxDiag.Mcp.Tests;

public sealed class LockTests : IDisposable
{
    private static readonly LinuxDiagOptions Options = LinuxDiagOptions.FromEnvironment(new System.Collections.Hashtable());

    private readonly string _root = Directory.CreateDirectory(
        Path.Combine(Path.GetTempPath(), $"ld-locks-{Guid.NewGuid():N}")).FullName;

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
    }

    private static LinuxLockInspector Locks() => new(new LinuxProcessTable(), new LinuxPrivilegeProbe());

    private static LinuxHandleInspector Handles() => new(new LinuxProcessTable(), new LinuxPrivilegeProbe(), Options);

    [Fact]
    public void A_missing_path_says_so_instead_of_reporting_no_holders()
    {
        var summary = LockTools.RenderLockSummary(new LockQuery("/nope", false, [], false, []));

        Assert.Contains("/nope does not exist", summary, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unconfirmed_holder_and_a_waiter_are_each_labelled()
    {
        var summary = LockTools.RenderLockSummary(new LockQuery("/var/lib/x.lock", true,
        [
            new LockHolder(10, "agent", LockHolderKind.Flock, "write", false, false, null, false),
            new LockHolder(11, "installer", LockHolderKind.Flock, "write", true, true, null, true),
        ], false, ["Not running as root."]));

        Assert.Contains("named by /proc/locks only", summary, StringComparison.Ordinal);
        Assert.Contains("do not act on this PID", summary, StringComparison.Ordinal);
        Assert.Contains("WAITING for the lock", summary, StringComparison.Ordinal);
        Assert.StartsWith("WARNING: Not running as root.", summary, StringComparison.Ordinal);
    }

    [LinuxFact]
    public void Path_handle_search_finds_an_open_file_by_name_and_by_another_name_for_the_same_file()
    {
        var file = Path.Combine(_root, "held.dat");
        var alias = Path.Combine(_root, "alias.dat");
        using var stream = new FileStream(file, FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite);
        LockParserTests.Run("ln", file, alias);

        var byName = Handles().Search("held.dat", false, CancellationToken.None);
        var byIdentity = Handles().Search(alias, false, CancellationToken.None);

        Assert.Contains(byName.Entries, e => e.ProcessId == Environment.ProcessId && e.Name == file);
        Assert.Contains(byIdentity.Entries, e => e.ProcessId == Environment.ProcessId && e.Name == file);
        Assert.False(byName.ProcessScoped);
    }

    [LinuxFact]
    public void Who_locks_path_names_this_process_as_the_flock_holder_confirmed_through_its_open_file()
    {
        // .NET takes flock(LOCK_EX) for FileShare.None on Unix, so this stream holds a real flock.
        var file = Path.Combine(_root, "agent.lock");
        using var stream = new FileStream(file, FileMode.Create, FileAccess.ReadWrite, FileShare.None);

        var query = Locks().Query(file, CancellationToken.None);

        var holder = Assert.Single(query.Holders, h => h.ProcessId == Environment.ProcessId);
        Assert.Equal(LockHolderKind.Flock, holder.Kind);
        Assert.True(holder.Confirmed);
        Assert.False(holder.Waiting);
        Assert.True(query.PathExists);
    }

    [LinuxFact]
    public void A_process_blocked_on_the_lock_is_listed_as_waiting()
    {
        var file = Path.Combine(_root, "busy.lock");
        using var stream = new FileStream(file, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
        using var waiter = Process.Start(new ProcessStartInfo("flock", [file, "true"]))!;
        try
        {
            LockHolder? waiting = null;
            var watch = Stopwatch.StartNew();
            while (waiting is null && watch.Elapsed < TimeSpan.FromSeconds(10))
            {
                waiting = Locks().Query(file, CancellationToken.None).Holders
                    .FirstOrDefault(h => h.ProcessId == waiter.Id && h.Waiting);
                if (waiting is null)
                {
                    Thread.Sleep(50);
                }
            }

            Assert.NotNull(waiting);
        }
        finally
        {
            waiter.Kill();
        }
    }

    [LinuxFact]
    public void A_file_merely_open_is_an_open_holder_with_its_access_mode()
    {
        // A child shell holds it, not this process: .NET takes a shared flock on every FileStream it opens
        // on Unix, so a file this test process opened would never be "merely open".
        var file = Path.Combine(_root, "open.log");
        using var child = Process.Start(new ProcessStartInfo("sh", ["-c", $"exec 3>'{file}'; exec sleep 30"]))!;
        try
        {
            LockHolder? holder = null;
            var watch = Stopwatch.StartNew();
            while (holder is null && watch.Elapsed < TimeSpan.FromSeconds(10))
            {
                holder = Locks().Query(file, CancellationToken.None).Holders.FirstOrDefault(h => h.ProcessId == child.Id);
                if (holder is null)
                {
                    Thread.Sleep(50);
                }
            }

            Assert.NotNull(holder);
            Assert.Equal(LockHolderKind.Open, holder.Kind);
            Assert.Equal("write", holder.Access);
        }
        finally
        {
            child.Kill();
        }
    }

    [LinuxFact]
    public void A_running_copy_of_a_binary_is_held_as_executing_the_text_file_busy_case()
    {
        var binary = Path.Combine(_root, "ld-sleep");
        File.Copy("/usr/bin/sleep", binary);
        File.SetUnixFileMode(binary, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        using var child = Process.Start(binary, "60");
        try
        {
            LockHolder? holder = null;
            var watch = Stopwatch.StartNew();
            while (holder is null && watch.Elapsed < TimeSpan.FromSeconds(10))
            {
                holder = Locks().Query(binary, CancellationToken.None).Holders
                    .FirstOrDefault(h => h.ProcessId == child.Id && h.Kind == LockHolderKind.Executing);
                if (holder is null)
                {
                    Thread.Sleep(50);
                }
            }

            Assert.NotNull(holder);
            Assert.DoesNotContain(Locks().Query(binary, CancellationToken.None).Holders,
                h => h.ProcessId == child.Id && h.Kind == LockHolderKind.Mapped);
        }
        finally
        {
            child.Kill();
        }
    }

    [UnprivilegedLinuxFact]
    public void A_path_this_account_cannot_look_up_is_a_permission_refusal_not_does_not_exist()
    {
        // /root is 0700 on Ubuntu and Debian.
        var ex = Assert.Throws<HandleQueryException>(() => Locks().Query("/root/.profile", CancellationToken.None));

        Assert.Contains("permission denied", ex.Message, StringComparison.Ordinal);
    }
}
