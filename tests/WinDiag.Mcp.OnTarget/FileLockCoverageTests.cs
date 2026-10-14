using System.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.External;
using WinDiag.Mcp.Diagnostics.Handles;
using WinDiag.Mcp.Diagnostics.Locks;
using Xunit.Abstractions;

namespace WinDiag.Mcp.OnTarget;

/// <summary>
/// Characterises what Restart Manager can and cannot see, against real locks on a real machine.
/// </summary>
/// <remarks>
/// <para>These tests exist to pin a <em>boundary</em>, not to confirm a happy path. Restart Manager is
/// the default backing for <c>who_locks_path</c> precisely because it needs no elevation, but it was
/// designed for installer reboot-avoidance and does not report every holder. The tool's wording
/// depends on that limitation being real and stable, so it is asserted rather than assumed.</para>
/// <para>Self-verifying by construction: the test creates the lock it then goes looking for, so there
/// are no fixtures to keep in sync and no ambiguity about the expected answer.</para>
/// </remarks>
[Trait("Category", "OnTarget")]
public sealed class FileLockCoverageTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"windiag-lock-{Guid.NewGuid():N}.tmp");

    private static ILockInspector Locks() =>
        new RestartManagerLockInspector(NullLogger<RestartManagerLockInspector>.Instance);

    private static IHandleInspector Handles() =>
        new HandleExeInspector(
            new ExternalToolRunner(new ToolLocator(), new WinDiagOptions(), NullLogger<ExternalToolRunner>.Instance),
            new ToolLocator(),
            new WindowsPrivilegeProbe(),
            new WinDiagOptions(),
            new NativeProcessTable());

    [Fact]
    public void Finds_a_file_that_this_very_process_is_holding_open()
    {
        using var stream = new FileStream(_path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);

        var result = Locks().WhoLocks(_path, CancellationToken.None);

        var self = Environment.ProcessId;
        Assert.Contains(result.Holders, h => h.ProcessId == self);

        var holder = result.Holders.First(h => h.ProcessId == self);
        Assert.True(holder.StillRunning);

        // Even a correct, complete-looking answer must not claim to be exhaustive.
        Assert.False(result.Exhaustive);
    }

    [Fact]
    public void Reports_a_live_holder_as_running()
    {
        using (new FileStream(_path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
        {
            var result = Locks().WhoLocks(_path, CancellationToken.None);

            // Assert the holder exists before asserting anything about it. An Assert.All over a
            // possibly-empty filtered sequence passes unconditionally, which would keep this test
            // green even if Restart Manager stopped reporting the current process entirely.
            var self = Assert.Single(result.Holders, h => h.ProcessId == Environment.ProcessId);
            Assert.True(self.StillRunning, "the running test process was reported as exited");
            Assert.NotNull(self.StartedAt);
        }
    }

    [RequiresElevatedHandleExeFact]
    public async Task Exhaustive_search_covers_registry_keys_not_just_files()
    {
        // The tripwire for the -a flag. handle.exe without -a "will dump all file references" and
        // nothing else, so this returns zero Key rows while path_handle_search's description promises
        // registry keys and who_locks_path points at it as the exhaustive answer. Every other test in
        // the suite searches a file name, so this is the only one that fails if -a is dropped.
        var result = await Handles().SearchAsync(
            @"Software\Microsoft\Windows\CurrentVersion", includeAllObjectTypes: true, CancellationToken.None);

        output.WriteLine($"matched {result.TotalMatched}, types: " +
                         string.Join(", ", result.Entries.Select(e => e.Type).Distinct()));

        Assert.Contains(result.Entries, e => e.Type.Equals("Key", StringComparison.OrdinalIgnoreCase));
    }

    [RequiresElevatedHandleExeFact]
    public async Task Exhaustive_search_finds_a_holder_in_another_process()
    {
        // A child process holds the file. It never registers with Restart Manager, which is the
        // population who_locks_path is documented to potentially miss.
        using var holder = StartFileHolder(_path);

        try
        {
            await WaitForLock(_path);

            var viaRestartManager = Locks().WhoLocks(_path, CancellationToken.None);
            output.WriteLine(
                $"Restart Manager reported {viaRestartManager.Holders.Count} holder(s): " +
                string.Join(", ", viaRestartManager.Holders.Select(h => $"{h.ProcessName}/{h.ProcessId}")));

            var viaHandle = await Handles().SearchAsync(
                Path.GetFileName(_path), includeAllObjectTypes: false, CancellationToken.None);
            output.WriteLine($"handle.exe reported {viaHandle.TotalMatched} match(es)");

            // The exhaustive path must find it. This is the guarantee that makes who_locks_path's
            // "run path_handle_search" advice worth giving.
            Assert.Contains(viaHandle.Entries, e => e.ProcessId == holder.Id);
            Assert.True(viaHandle.Elevated);

            // The holder ran throughout, so the process table must confirm the image name handle.exe
            // printed for it. If handle.exe names processes differently from NtQuerySystemInformation,
            // every search would degrade to unattributable rows, and only this machine can show it.
            Assert.False(viaHandle.UnconfirmedImage);
            Assert.All(viaHandle.Entries, e => Assert.False(e.Unproven));
        }
        finally
        {
            KillQuietly(holder);
        }
    }

    [RequiresElevatedHandleExeFact]
    public async Task A_search_for_the_tools_own_working_directory_is_fully_attributed()
    {
        // handle64.exe runs in the directory it inherits -- C:\Windows\System32 under the SCM -- and may list
        // its own handle on it, and its console host's. Neither is in either reading of the process table: the
        // tool is confirmed by the PID it was started as, but the console host is not. If this goes red,
        // UnparsedRows says which rows a search for System32 loses on a real service, on every run.
        var directory = Environment.CurrentDirectory;

        var result = await Handles().SearchAsync(directory, includeAllObjectTypes: false, CancellationToken.None);

        foreach (var entry in result.Entries)
        {
            output.WriteLine($"{entry.ProcessName}/{entry.ProcessId} {entry.Type} unproven={entry.Unproven} {entry.Name}");
        }

        output.WriteLine($"unattributable rows: {result.UnparsedRows}; unconfirmed image: {result.UnconfirmedImage}");
        Assert.Contains(result.Entries, e => e.ProcessId == Environment.ProcessId);
        Assert.Equal(0, result.UnparsedRows);
        Assert.False(result.UnconfirmedImage);
    }

    [RequiresElevatedHandleExeFact]
    public async Task A_line_break_in_an_object_name_never_puts_a_row_on_another_pid()
    {
        // The parser cannot see whether handle.exe escapes a line break in a name; this asks the real
        // tool. The event's name carries, after an LF, a whole row naming PID 4 (System). A backslash after
        // the break would be read as a namespace separator, so the forged row avoids one.
        var marker = $"sysdiag-break-{Guid.NewGuid():N}";
        var forged = $"forged.exe,4,File,SYSTEM,0x00000004,{marker}-victim";
        using var named = new EventWaitHandle(false, EventResetMode.ManualReset, $"Local\\{marker}\n{forged}");

        var search = await Handles().SearchAsync(marker, includeAllObjectTypes: true, CancellationToken.None);
        var scoped = await Handles().ListForProcessAsync(Environment.ProcessId, includeAllObjectTypes: true, CancellationToken.None);

        foreach (var entry in search.Entries)
        {
            output.WriteLine($"search: {entry.ProcessName}/{entry.ProcessId} {entry.Type} {entry.HandleValue} unproven={entry.Unproven} {entry.Name}");
        }

        // Recorded rather than asserted: whether handle.exe escapes the break decides these, and either is safe.
        output.WriteLine($"search unattributable rows: {search.UnparsedRows}; scoped unproven rows: {scoped.Entries.Count(e => e.Unproven)}");

        Assert.DoesNotContain(search.Entries, e => e.ProcessId == 4);
        Assert.Contains(search.Entries, e => e.ProcessId == Environment.ProcessId && e.Type == "Event");
        Assert.DoesNotContain(scoped.Entries, e => e.ProcessId != Environment.ProcessId);
    }

    /// <summary>Spawns a process that opens the file exclusively and holds it.</summary>
    private static Process StartFileHolder(string path)
    {
        var script =
            $"$f=[System.IO.File]::Open('{path}','OpenOrCreate','ReadWrite','None'); " +
            "Start-Sleep -Seconds 60; $f.Close()";

        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true
        };

        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(script);

        return Process.Start(startInfo)
               ?? throw new InvalidOperationException("could not start the file-holder process");
    }

    /// <summary>Waits until the file is genuinely locked, so the test never races the child.</summary>
    private static async Task WaitForLock(string path)
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            try
            {
                using var probe = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException)
            {
                return;
            }

            await Task.Delay(100);
        }

        throw new TimeoutException("the file-holder process never took an exclusive lock");
    }

    private static void KillQuietly(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // Nothing useful to do; the temp file is cleaned up either way.
        }
    }

    public void Dispose()
    {
        try
        {
            if (File.Exists(_path))
            {
                File.Delete(_path);
            }
        }
        catch (IOException)
        {
            // Still held by a child that outlived the kill. The temp directory will reclaim it.
        }
    }
}
