using Microsoft.Extensions.Logging.Abstractions;
using WinDiag.Mcp.Diagnostics.Control;
using WinDiag.Mcp.Diagnostics.Modules;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp.Tests;

public sealed class ProcessActionParsingTests
{
    [Theory]
    [InlineData("terminate", ProcessAction.Terminate)]
    [InlineData("KILL", ProcessAction.Terminate)]
    [InlineData(" suspend ", ProcessAction.Suspend)]
    [InlineData("freeze", ProcessAction.Suspend)]
    [InlineData("resume", ProcessAction.Resume)]
    public void Recognises_the_documented_actions(string input, ProcessAction expected)
    {
        Assert.Equal(expected, ControlTools.ParseProcessAction(input));
    }

    [Fact]
    public void Rejects_an_unknown_action_rather_than_guessing()
    {
        // Guessing here picks between freezing a process and ending it.
        var ex = Assert.Throws<ArgumentException>(() => ControlTools.ParseProcessAction("stop"));

        Assert.Contains("'terminate', 'suspend' or 'resume'", ex.Message);
    }
}

public sealed class ServiceActionParsingTests
{
    [Theory]
    [InlineData("start", ServiceAction.Start)]
    [InlineData("STOP", ServiceAction.Stop)]
    [InlineData(" restart ", ServiceAction.Restart)]
    [InlineData("bounce", ServiceAction.Restart)]
    public void Recognises_the_documented_actions(string input, ServiceAction expected)
    {
        Assert.Equal(expected, ControlTools.ParseServiceAction(input));
    }

    [Fact]
    public void Rejects_an_unknown_action()
    {
        Assert.Throws<ArgumentException>(() => ControlTools.ParseServiceAction("kill"));
    }
}

/// <summary>
/// The identity check that stands between a stale PID and the wrong process being killed.
/// </summary>
public sealed class ProcessIdentityTests
{
    [Theory]
    [InlineData("notepad", "notepad")]
    [InlineData("notepad", "notepad.exe")]
    [InlineData("notepad.exe", "notepad")]
    [InlineData("NOTEPAD", "notepad.exe")]
    public void Accepts_the_same_image_with_or_without_the_extension(string actual, string expected)
    {
        // process_list reports "notepad.exe" while Process.ProcessName gives "notepad"; rejecting on
        // that difference would only teach callers to stop passing the name at all.
        Assert.True(WindowsProcessController.NamesMatch(actual, expected));
    }

    [Theory]
    [InlineData("svchost", "notepad")]
    [InlineData("explorer.exe", "iexplore.exe")]
    public void Rejects_a_different_image(string actual, string expected)
    {
        Assert.False(WindowsProcessController.NamesMatch(actual, expected));
    }

    [Fact]
    public void Treats_a_clearly_different_start_time_as_a_recycled_pid()
    {
        var reported = new DateTimeOffset(2026, 8, 14, 10, 0, 0, TimeSpan.Zero);

        Assert.True(WindowsProcessController.IsPidReused(reported, reported.AddMinutes(5)));
        Assert.False(WindowsProcessController.IsPidReused(reported, reported.AddMilliseconds(800)));
        Assert.False(WindowsProcessController.IsPidReused(null, reported));
    }
}

public sealed class ProcessControlRefusalTests
{
    private static WindowsProcessController Controller() =>
        new(NullLogger<WindowsProcessController>.Instance);

    [Fact]
    public void Refuses_a_pid_whose_name_does_not_match_what_the_caller_expected()
    {
        // The whole point of requiring a name. Acting on a recycled PID means killing an innocent
        // process, and the caller would never know which.
        //
        // A real child rather than this process: the self-refusal is checked first and deliberately so,
        // which would mask the check under test.
        var startInfo = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "cmd.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true
        };
        startInfo.ArgumentList.Add("/c");
        startInfo.ArgumentList.Add("ping -n 30 127.0.0.1");

        using var target = System.Diagnostics.Process.Start(startInfo)!;

        try
        {
            Thread.Sleep(250);

            var ex = Assert.Throws<ProcessControlException>(
                () => Controller().Control(
                    target.Id, "definitely-not-this-process", ProcessAction.Terminate, CancellationToken.None));

            Assert.Contains("Nothing has been done", ex.Message);
            Assert.Contains("PIDs are reused", ex.Message);

            // The refusal must be real, not cosmetic.
            target.Refresh();
            Assert.False(target.HasExited, "the process was killed despite the name mismatch");
        }
        finally
        {
            if (!target.HasExited)
            {
                target.Kill(entireProcessTree: true);
            }
        }
    }

    [Fact]
    public void Refuses_to_act_on_the_server_itself()
    {
        var self = System.Diagnostics.Process.GetCurrentProcess().ProcessName;

        var ex = Assert.Throws<ProcessControlException>(
            () => Controller().Control(
                Environment.ProcessId, self, ProcessAction.Terminate, CancellationToken.None));

        Assert.Contains("own process", ex.Message);
    }

    [Fact]
    public void Refuses_a_core_windows_process()
    {
        // PID 4 is System on every Windows machine. Ending it bugchecks the box.
        var ex = Assert.Throws<ProcessControlException>(
            () => Controller().Control(4, "System", ProcessAction.Terminate, CancellationToken.None));

        Assert.Contains("core Windows process", ex.Message);
    }

    [Fact]
    public void Explains_a_pid_that_does_not_exist()
    {
        var ex = Assert.Throws<ProcessControlException>(
            () => Controller().Control(-1, "anything", ProcessAction.Terminate, CancellationToken.None));

        Assert.Contains("Nothing has been done", ex.Message);
    }
}

public sealed class ServiceControlRefusalTests
{
    private static WindowsServiceControllerAdapter Controller() =>
        new(NullLogger<WindowsServiceControllerAdapter>.Instance);

    [Theory]
    [InlineData("RpcSs")]
    [InlineData("DcomLaunch")]
    [InlineData("Winmgmt")]
    [InlineData("EventLog")]
    [InlineData("plugplay")]
    public void Refuses_to_stop_a_core_service(string service)
    {
        // Winmgmt is the pointed one: stopping it breaks process_list, so the tool would be sawing off
        // the branch it is standing on.
        var ex = Assert.Throws<ServiceControlException>(
            () => Controller().Control(service, ServiceAction.Stop, CancellationToken.None));

        Assert.Contains("core Windows service", ex.Message);
        Assert.Contains("Nothing has been done", ex.Message);
    }

    [Fact]
    public void Refuses_to_restart_a_core_service_too()
    {
        // A restart is a stop followed by a start; the machine is just as broken in between.
        Assert.Throws<ServiceControlException>(
            () => Controller().Control("RpcSs", ServiceAction.Restart, CancellationToken.None));
    }

    [Fact]
    public void Allows_starting_a_core_service_that_is_already_meant_to_run()
    {
        // Starting one is not dangerous, and refusing it would block the obvious recovery step after
        // something else stopped it. This should fail for being already running, not for being refused.
        var ex = Record.Exception(
            () => Controller().Control("EventLog", ServiceAction.Start, CancellationToken.None));

        if (ex is ServiceControlException refused)
        {
            Assert.DoesNotContain("core Windows service", refused.Message);
        }
    }

    [Fact]
    public void Explains_a_service_that_does_not_exist()
    {
        var ex = Assert.Throws<ServiceControlException>(
            () => Controller().Control($"windiag-absent-{Guid.NewGuid():N}", ServiceAction.Stop, CancellationToken.None));

        Assert.Contains("service_config", ex.Message);
    }
}

public sealed class ControlRenderingTests
{
    [Fact]
    public void A_suspend_reminds_the_caller_to_resume()
    {
        // A forgotten suspended process is indistinguishable from a hung one to whoever looks next.
        var result = new ProcessControlResult(
            42, "app", DateTimeOffset.UnixEpoch, ProcessAction.Suspend, "Suspended.");

        Assert.Contains("Remember to resume", ControlTools.RenderProcess(result));
    }

    [Fact]
    public void A_terminate_does_not_nag_about_resuming()
    {
        var result = new ProcessControlResult(
            42, "app", DateTimeOffset.UnixEpoch, ProcessAction.Terminate, "Terminated.");

        Assert.DoesNotContain("Remember to resume", ControlTools.RenderProcess(result));
    }

    [Fact]
    public void Stopping_a_service_names_what_else_it_took_down()
    {
        // Restarting the named service does not bring dependents back, so leaving them unmentioned
        // means a half-restored machine that looks fixed.
        var result = new ServiceControlResult(
            "Spooler", "Print Spooler", ServiceAction.Stop, "Running", "Stopped",
            ["Fax", "PrintNotify"], "Stop: Running -> Stopped.");

        var summary = ControlTools.RenderService(result);

        Assert.Contains("Fax", summary);
        Assert.Contains("PrintNotify", summary);
        Assert.Contains("Start these again individually", summary);
    }
}

public sealed class ModuleRenderingTests
{
    private static LoadedModule Module(string name, string? verdict = null, bool collision = false) =>
        new(name, $@"C:\Windows\System32\{name}", "0x7FF800000000", 1_234_567, "10.0.19045.1", "Microsoft",
            verdict, null, PreferredBase: "0x10000000", Relocated: true, BaseCollision: collision);

    private static ModuleListResult Result(
        IReadOnlyList<LoadedModule> modules,
        string? limitation = null,
        bool truncated = false,
        int unsigned = 0,
        int collisions = 0) =>
        new(42, "app", modules, modules.Count, truncated, unsigned, limitation, collisions);

    [Fact]
    public void Leads_with_a_partial_read_because_a_short_list_looks_like_a_small_process()
    {
        var summary = ModuleTools.Render(
            Result([Module("kernel32.dll")], limitation: "Only part of the module list could be read."),
            null, false);

        Assert.StartsWith("WARNING", summary);
    }

    [Fact]
    public void Says_signatures_were_not_checked_rather_than_implying_they_were_clean()
    {
        var summary = ModuleTools.Render(Result([Module("kernel32.dll")]), null, verified: false);

        Assert.Contains("Signatures were not checked", summary);
    }

    [Fact]
    public void Points_at_the_unsigned_modules_when_verification_ran()
    {
        var summary = ModuleTools.Render(
            Result([Module("evil.dll", "Unsigned")], unsigned: 1), null, verified: true);

        Assert.Contains("[UNSIGNED]", summary);
        Assert.Contains("1 of the modules returned is unsigned", summary);
        Assert.Contains("worth looking at first", summary);
    }

    [Fact]
    public void Counts_several_unsigned_modules_without_mangling_the_sentence()
    {
        var summary = ModuleTools.Render(
            Result([Module("a.dll", "Unsigned"), Module("b.dll", "Untrusted")], unsigned: 2),
            null, verified: true);

        Assert.Contains("2 of the modules returned are unsigned", summary);
    }

    [Fact]
    public void Confirms_a_clean_result_explicitly()
    {
        var summary = ModuleTools.Render(Result([Module("kernel32.dll", "Valid")]), null, verified: true);

        Assert.Contains("signed and trusted", summary);
        Assert.DoesNotContain("[VALID]", summary);
    }

    [Fact]
    public void Stays_quiet_about_relocation_when_it_is_only_aslr()
    {
        // Every module in this result has Relocated: true, because on any modern Windows they all are.
        // Flagging that would bury the collisions in noise, which is the whole reason the two are
        // separate fields.
        var summary = ModuleTools.Render(Result([Module("kernel32.dll"), Module("user32.dll")]), null, false);

        Assert.DoesNotContain("REBASED", summary);
        Assert.DoesNotContain("occupied that range", summary);
    }

    [Fact]
    public void Calls_out_a_module_that_was_moved_despite_asking_not_to_be()
    {
        var summary = ModuleTools.Render(
            Result([Module("legacy.dll", collision: true)], collisions: 1), null, false);

        Assert.Contains("[REBASED from 0x10000000]", summary);
        Assert.Contains("1 module was", summary);
        Assert.Contains("already occupied that range", summary);
    }

    [Fact]
    public void Reports_an_empty_filter_match_as_a_real_answer()
    {
        // Distinct from an enumeration that failed: that one throws rather than reaching the renderer,
        // precisely so "0 modules" can only ever mean "the filter matched nothing".
        var summary = ModuleTools.Render(Result([]), "nosuchmodule", false);

        Assert.Contains("0 modules in app", summary);
        Assert.Contains("matching 'nosuchmodule'", summary);
        Assert.DoesNotContain("WARNING", summary);
    }
}

/// <summary>
/// The PE header read behind the relocation fields.
/// </summary>
/// <remarks>
/// Fixture-free on purpose: every Windows machine ships images of both bitnesses, and asserting
/// against the real ones is what catches an offset that is right for PE32 and wrong for PE32+.
/// </remarks>
public sealed class PeImageReaderTests
{
    [Fact]
    public void Reads_the_preferred_base_of_a_real_system_image()
    {
        var kernel32 = Path.Combine(Environment.SystemDirectory, "kernel32.dll");

        var header = PeImageReader.TryRead(kernel32);

        Assert.NotNull(header);
        Assert.NotEqual(0UL, header!.Value.ImageBase);

        // Everything Microsoft ships has been built /DYNAMICBASE for over a decade. If this ever fails,
        // the flag offset is wrong rather than the assumption.
        Assert.True(header.Value.DynamicBase);
    }

    [Fact]
    public void Reads_this_test_assembly_too()
    {
        var header = PeImageReader.TryRead(typeof(PeImageReaderTests).Assembly.Location);

        Assert.NotNull(header);
        Assert.NotEqual(0UL, header!.Value.ImageBase);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Returns_null_rather_than_throwing_on_a_path_it_cannot_use(string path)
    {
        Assert.Null(PeImageReader.TryRead(path));
    }

    [Fact]
    public void Returns_null_for_a_file_that_is_not_a_pe_image()
    {
        // A module whose file has been replaced or truncated under the running process is normal; it
        // must cost that one module's relocation data and nothing else.
        var temp = Path.Combine(Path.GetTempPath(), $"windiag-notpe-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(temp, [.. Enumerable.Repeat((byte)0x41, 2048)]);

        try
        {
            Assert.Null(PeImageReader.TryRead(temp));
        }
        finally
        {
            File.Delete(temp);
        }
    }

    [Fact]
    public void Returns_null_for_a_file_too_short_to_have_a_header()
    {
        var temp = Path.Combine(Path.GetTempPath(), $"windiag-short-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(temp, [0x4D, 0x5A]);

        try
        {
            Assert.Null(PeImageReader.TryRead(temp));
        }
        finally
        {
            File.Delete(temp);
        }
    }

    [Fact]
    public void Returns_null_for_a_path_that_does_not_exist()
    {
        Assert.Null(PeImageReader.TryRead(Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.dll")));
    }

    [Fact]
    public void Sees_an_image_that_did_not_opt_into_aslr()
    {
        // Everything on a modern Windows install is /DYNAMICBASE, so the positive assertion above would
        // pass just as happily if the offset were wrong and the read were picking up some other
        // always-nonzero field. This clears exactly that bit in a copy of a real image and requires the
        // reader to notice -- and requires ImageBase to come back unchanged, which is what proves the
        // byte that moved was the one intended.
        var source = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
        var before = PeImageReader.TryRead(source);
        Assert.NotNull(before);
        Assert.True(before!.Value.DynamicBase);

        var copy = Path.Combine(Path.GetTempPath(), $"windiag-noaslr-{Guid.NewGuid():N}.dll");
        File.Copy(source, copy, overwrite: true);

        try
        {
            var bytes = File.ReadAllBytes(copy);
            var peOffset = BitConverter.ToInt32(bytes, 0x3C);
            var dllCharacteristics = peOffset + 4 + 20 + 70;

            var flags = BitConverter.ToUInt16(bytes, dllCharacteristics);
            BitConverter.TryWriteBytes(bytes.AsSpan(dllCharacteristics), (ushort)(flags & ~0x0040));
            File.WriteAllBytes(copy, bytes);

            var after = PeImageReader.TryRead(copy);

            Assert.NotNull(after);
            Assert.False(after!.Value.DynamicBase);
            Assert.Equal(before.Value.ImageBase, after.Value.ImageBase);
        }
        finally
        {
            File.Delete(copy);
        }
    }
}

/// <summary>
/// What the inspector does against real processes on this machine.
/// </summary>
public sealed class ModuleInspectorTests
{
    private static WindowsModuleInspector Inspector() =>
        new(new WinDiag.Mcp.Diagnostics.Signatures.WinTrustSignatureInspector(),
            WinDiag.Mcp.Configuration.WinDiagOptions.FromEnvironment(new System.Collections.Hashtable()));

    [Fact]
    public void Lists_its_own_modules_with_a_preferred_base_for_each()
    {
        var result = Inspector().List(Environment.ProcessId, null, false, CancellationToken.None);

        Assert.NotEmpty(result.Modules);
        Assert.Null(result.Limitation);

        // The relocation fields are the point: a base address with nothing to compare it against is a
        // number the caller cannot act on.
        Assert.All(result.Modules, m => Assert.NotNull(m.PreferredBase));
        Assert.All(result.Modules, m => Assert.NotNull(m.Relocated));
    }

    [Fact]
    public void Refuses_a_pid_that_is_not_running_rather_than_returning_nothing()
    {
        var ex = Assert.Throws<ModuleQueryException>(
            () => Inspector().List(-1, null, false, CancellationToken.None));

        Assert.Contains("process_list", ex.Message);
    }

    [Fact]
    public void Names_the_bitness_fix_when_nothing_at_all_can_be_read()
    {
        // PID 4 is System: kernel-only, so module enumeration fails outright. An empty list with a
        // warning attached would still headline as "0 modules"; a refusal that names the cause will not
        // be misread. This is the same path a win-x86 server hits against every 64-bit process.
        var ex = Assert.Throws<ModuleQueryException>(
            () => Inspector().List(4, null, false, CancellationToken.None));

        Assert.Contains("No modules could be read", ex.Message);
        Assert.DoesNotContain("Only part", ex.Message);
    }
}
