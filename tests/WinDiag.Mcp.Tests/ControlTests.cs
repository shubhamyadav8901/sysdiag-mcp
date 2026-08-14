using Microsoft.Extensions.Logging.Abstractions;
using WinDiag.Mcp.Diagnostics.Control;
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
