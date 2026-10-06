using System.Diagnostics;
using System.Management;
using System.ServiceProcess;
using DiagRelay.Mcp.Tests;
using Microsoft.Extensions.Logging.Abstractions;
using WinDiag.Mcp.Diagnostics.Control;

namespace WinDiag.Mcp.Tests;

/// <summary>The real probe against the machine the suite runs on -- CI's windows-latest runner, which is elevated.</summary>
/// <remarks>
/// <para>Every other process_control test fakes the probe, so they prove the controller refuses on what the probe
/// says, not that the probe says it. A wrong struct layout, a wrong type filter or a broken resume loop would make
/// ServicesHostedBy answer "nothing" for the RpcSs host -- which is not a critical process, so nothing else would
/// stop process_control ending it -- and those tests would stay green.</para>
/// <para>Nothing here can end or freeze a process the test does not own. The refusals are asked of
/// RequireUnprotected directly, which never reaches the code that acts; only the test's own child is ever
/// signalled.</para>
/// </remarks>
public sealed class ProcessProtectionProbeTests
{
    /// <summary>The PID hosting a service, from WMI: a second source, so the probe is not checked against itself.</summary>
    private static int HostOf(string service)
    {
        using var searcher = new ManagementObjectSearcher($"SELECT ProcessId FROM Win32_Service WHERE Name = '{service}'");
        var pid = searcher.Get().Cast<ManagementObject>().Select(o => Convert.ToInt32(o["ProcessId"])).Single();
        Assert.True(pid != 0, $"{service} is not running here, so there is no host to ask about.");
        return pid;
    }

    private static WindowsProcessController Controller() =>
        new(NullLogger<WindowsProcessController>.Instance, new WindowsProcessProtectionProbe());

    [WindowsFact]
    public void Names_RpcSs_among_the_services_of_the_svchost_that_hosts_it()
    {
        var hosted = new WindowsProcessProtectionProbe().ServicesHostedBy(HostOf("RpcSs"));

        Assert.Contains("RpcSs", hosted, StringComparer.OrdinalIgnoreCase);
    }

    [WindowsFact]
    public void Names_DcomLaunch_among_the_services_of_the_svchost_that_hosts_it()
    {
        var hosted = new WindowsProcessProtectionProbe().ServicesHostedBy(HostOf("DcomLaunch"));

        Assert.Contains("DcomLaunch", hosted, StringComparer.OrdinalIgnoreCase);
    }

    [WindowsFact]
    public void Reading_the_service_list_in_small_batches_misses_no_running_service_and_keeps_each_ones_host()
    {
        // The default buffer holds a typical machine's whole list, so the resume path never runs unless forced.
        // Services start and stop on their own while this runs, so only those running both before and after are
        // owed; any of them missing means a batch was dropped.
        const int batchBytes = 1024;
        var before = RunningWin32Services();
        var paged = new WindowsProcessProtectionProbe(batchBytes).ActiveServices();
        var after = RunningWin32Services();
        before.IntersectWith(after);

        // An entry is two pointers and nine DWORDs before its names, so 1 KB cannot hold this many in one batch.
        Assert.True(paged.Count > batchBytes / (2 * IntPtr.Size + 9 * sizeof(uint)),
            $"Only {paged.Count} services were listed, so the list may have fitted in one batch and the resume path did not run.");
        Assert.Empty(before.Except(paged.Select(s => s.Name), StringComparer.OrdinalIgnoreCase));
        Assert.Equal(paged.Count, paged.Select(s => s.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count());

        // The PID is the field the refusal keys on; a layout off by one field reads a neighbour instead.
        var rpcss = paged.Single(s => string.Equals(s.Name, "RpcSs", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(HostOf("RpcSs"), rpcss.ProcessId);
    }

    [ElevatedFact]
    public void Reports_wininit_and_every_csrss_critical_and_this_test_host_not()
    {
        // Both are protected processes, which refuse the PROCESS_ALL_ACCESS that Process.Handle asks for even to
        // an elevated caller; reading the flag needs only PROCESS_QUERY_LIMITED_INFORMATION, which they grant.
        var probe = new WindowsProcessProtectionProbe();
        using var wininit = Process.GetProcessesByName("wininit").Single();
        var csrss = Process.GetProcessesByName("csrss");
        using var self = Process.GetCurrentProcess();
        try
        {
            Assert.True(probe.IsCritical(wininit), "wininit was not reported critical");
            Assert.NotEmpty(csrss);
            Assert.All(csrss, process => Assert.True(probe.IsCritical(process), $"csrss PID {process.Id} was not reported critical"));
            Assert.False(probe.IsCritical(self), "this test host was reported critical");
        }
        finally
        {
            foreach (var process in csrss)
            {
                process.Dispose();
            }
        }
    }

    [WindowsFact]
    public void Refuses_the_svchost_hosting_RpcSs_with_the_real_probe()
    {
        AssertRefusedForHosting("RpcSs");
    }

    [WindowsFact]
    public void Refuses_the_svchost_hosting_DcomLaunch_with_the_real_probe()
    {
        AssertRefusedForHosting("DcomLaunch");
    }

    [WindowsFact]
    public void Still_ends_a_process_the_test_owns_with_the_real_probe()
    {
        // The other half: a probe that failed closed on everything -- access denied on every handle, say --
        // would pass every refusal above and leave process_control unable to end anything.
        using var child = Process.Start(new ProcessStartInfo("ping.exe")
        {
            ArgumentList = { "-n", "30", "127.0.0.1" },
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
        })!;
        try
        {
            var result = Controller().Control(child.Id, child.ProcessName, ProcessAction.Terminate, CancellationToken.None);

            Assert.Equal(ProcessAction.Terminate, result.Action);
            Assert.True(child.WaitForExit(10_000), "the test's own child was not ended");
        }
        finally
        {
            if (!child.HasExited)
            {
                child.Kill();
            }
        }
    }

    private static void AssertRefusedForHosting(string service)
    {
        var pid = HostOf(service);
        using var host = Process.GetProcessById(pid);

        var ex = Assert.Throws<ProcessControlException>(
            () => Controller().RequireUnprotected(host, host.ProcessName, pid, ProcessAction.Terminate));

        // Not "it hosts {service}": a host that also runs another protected service lists both, in SCM order.
        Assert.Contains("service_control also refuses", ex.Message);
        Assert.Contains(service, ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Nothing has been done", ex.Message);
    }

    /// <summary>Running Win32 services by name, per ServiceController -- not the probe's own call.</summary>
    /// <remarks>Per-user service instances are left out: whether the SCM's SERVICE_WIN32 filter counts them is not
    /// what is under test, and none of them is one process_control protects.</remarks>
    private static HashSet<string> RunningWin32Services()
    {
        const int userServiceBit = 0x40;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var service in ServiceController.GetServices())
        {
            using (service)
            {
                if (service.Status == ServiceControllerStatus.Running && ((int)service.ServiceType & userServiceBit) == 0)
                {
                    names.Add(service.ServiceName);
                }
            }
        }

        return names;
    }
}
