using System.Collections;
using System.Diagnostics;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.Dumps;
using Xunit.Abstractions;

namespace WinDiag.Mcp.OnTarget;

/// <summary>
/// Captures real dumps of a child process this test starts.
/// </summary>
/// <remarks>
/// <para>Deliberately a <em>child</em>, not the test host. A process cannot reliably dump itself:
/// <c>MiniDumpWriteDump</c> suspends the target's threads, including the one making the call. An earlier
/// version of these tests dumped the test host and passed when run alone, then deadlocked the whole
/// suite under parallel load — an intermittent hang, which is the worst way to learn this.</para>
/// <para>Dumping another process is also what the tool is actually for, so this exercises the real path
/// rather than an artificial one. It needs no elevation, because the child runs as the same user.</para>
/// </remarks>
[Trait("Category", "OnTarget")]
public sealed class DumpCaptureTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"windiag-dumps-{Guid.NewGuid():N}");

    private readonly List<Process> _children = [];

    private IDumpWriter Writer() =>
        new MiniDumpWriter(
            WinDiagOptions.FromEnvironment(new Hashtable { ["WINDIAG_ARTIFACT_DIR"] = _directory }),
            new WindowsPrivilegeProbe());

    /// <summary>Starts a small, quiet, self-terminating process to act as the dump target.</summary>
    /// <param name="bitness">
    /// Which cmd.exe to run. <c>SysWOW64</c> gives a genuine 32-bit process on 64-bit Windows, which is
    /// the case Office add-ins and shell extension hosts fall into.
    /// </param>
    private Process StartTarget(string bitness = "System32")
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), bitness, "cmd.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true
        };

        // ping rather than timeout: it needs no console and keeps the process alive quietly.
        startInfo.ArgumentList.Add("/c");
        startInfo.ArgumentList.Add("ping -n 120 127.0.0.1");

        var process = Process.Start(startInfo)
                      ?? throw new InvalidOperationException("could not start the dump target");

        _children.Add(process);

        // Give it a moment to finish initialising so there is a real image to dump.
        Thread.Sleep(300);
        return process;
    }

    [Fact]
    public void Writes_a_mini_dump_with_a_valid_minidump_header()
    {
        var target = StartTarget();

        var dump = Writer().Capture(target.Id, DumpKind.Mini, CancellationToken.None);

        output.WriteLine($"{dump.Path} ({dump.SizeBytes:N0} bytes)");

        Assert.Equal(target.Id, dump.ProcessId);
        Assert.Equal("cmd", dump.ProcessName, ignoreCase: true);
        Assert.True(File.Exists(dump.Path), dump.Path);

        // "MDMP" is the minidump signature. Asserting it distinguishes a real dump from a file that was
        // merely created — exactly what a failed MiniDumpWriteDump would otherwise leave behind.
        using var stream = File.OpenRead(dump.Path);
        var magic = new byte[4];
        Assert.Equal(4, stream.Read(magic));
        Assert.Equal("MDMP"u8.ToArray(), magic);
    }

    [Fact]
    public void A_full_dump_is_larger_than_a_mini_dump_of_the_same_process()
    {
        var target = StartTarget();
        var writer = Writer();

        var mini = writer.Capture(target.Id, DumpKind.Mini, CancellationToken.None);
        var full = writer.Capture(target.Id, DumpKind.Full, CancellationToken.None);

        output.WriteLine($"mini={mini.SizeBytes:N0}  full={full.SizeBytes:N0}");

        // Proves the two flag sets genuinely differ rather than both writing the same thing.
        Assert.True(
            full.SizeBytes > mini.SizeBytes,
            $"full dump ({full.SizeBytes:N0}) was not larger than mini ({mini.SizeBytes:N0})");
    }

    [Fact]
    public void Two_captures_of_the_same_process_do_not_overwrite_each_other()
    {
        // Capturing repeatedly while chasing an intermittent fault is normal; silently replacing the
        // earlier capture would discard evidence.
        var target = StartTarget();
        var writer = Writer();

        var first = writer.Capture(target.Id, DumpKind.Mini, CancellationToken.None);
        Thread.Sleep(1100);
        var second = writer.Capture(target.Id, DumpKind.Mini, CancellationToken.None);

        Assert.NotEqual(first.Path, second.Path);
        Assert.True(File.Exists(first.Path));
        Assert.True(File.Exists(second.Path));
    }

    [Fact]
    public void Reports_a_path_another_machine_could_open()
    {
        var dump = Writer().Capture(StartTarget().Id, DumpKind.Mini, CancellationToken.None);

        Assert.NotNull(dump.UncPath);
        Assert.StartsWith($@"\\{Environment.MachineName}\", dump.UncPath);
        Assert.EndsWith(Path.GetFileName(dump.Path), dump.UncPath);
    }

    [Fact]
    public void Flags_a_32_bit_target_and_says_how_to_read_its_stacks()
    {
        if (!Environment.Is64BitOperatingSystem)
        {
            // On a 32-bit OS there is no WOW64 and nothing to warn about.
            return;
        }

        var target = StartTarget("SysWOW64");

        var dump = Writer().Capture(target.Id, DumpKind.Mini, CancellationToken.None);

        output.WriteLine($"wow64={dump.TargetIsWow64}, {dump.SizeBytes:N0} bytes");

        // Without this, the analyst opens the dump, sees thunk frames instead of the real call stacks,
        // and loses time to what looks like a corrupt capture.
        Assert.True(dump.TargetIsWow64, "a SysWOW64 process was not detected as 32-bit");

        var summary = Tools.DumpTools.Render(dump);
        Assert.Contains("!wow64exts.sw", summary);
        Assert.Contains("32-bit", summary);
    }

    [Fact]
    public void Does_not_warn_about_bitness_for_a_64_bit_target()
    {
        if (!Environment.Is64BitOperatingSystem)
        {
            return;
        }

        var dump = Writer().Capture(StartTarget().Id, DumpKind.Mini, CancellationToken.None);

        Assert.False(dump.TargetIsWow64);
        Assert.DoesNotContain("!wow64exts.sw", Tools.DumpTools.Render(dump));
    }

    [Fact]
    public void Refuses_to_dump_the_server_itself()
    {
        // Self-dump can deadlock, and a hang inside a long-lived elevated server is unrecoverable.
        var ex = Assert.Throws<DumpCaptureException>(
            () => Writer().Capture(Environment.ProcessId, DumpKind.Mini, CancellationToken.None));

        output.WriteLine(ex.Message);
        Assert.Contains("cannot reliably dump itself", ex.Message);
    }

    [Fact]
    public void Explains_a_pid_that_does_not_exist_rather_than_failing_obscurely()
    {
        var ex = Assert.Throws<DumpCaptureException>(
            () => Writer().Capture(-1, DumpKind.Mini, CancellationToken.None));

        output.WriteLine(ex.Message);
        Assert.Contains("process_list", ex.Message);
    }

    public void Dispose()
    {
        foreach (var child in _children)
        {
            try
            {
                if (!child.HasExited)
                {
                    child.Kill(entireProcessTree: true);
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // Already gone.
            }
            finally
            {
                child.Dispose();
            }
        }

        try
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
        catch (IOException)
        {
            // Temp will reclaim it.
        }
    }
}
