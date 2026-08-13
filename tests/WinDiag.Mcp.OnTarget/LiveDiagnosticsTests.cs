using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.Access;
using WinDiag.Mcp.Diagnostics.EventLogs;
using WinDiag.Mcp.Diagnostics.Processes;
using WinDiag.Mcp.Diagnostics.Services;
using WinDiag.Mcp.Diagnostics.SystemInfo;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit.Abstractions;

namespace WinDiag.Mcp.OnTarget;

/// <summary>
/// Exercises the remaining native inspectors against this machine.
/// </summary>
/// <remarks>
/// These read real system state, so assertions target facts that hold on any Windows box or that the
/// test establishes itself, never values specific to one machine.
/// </remarks>
[Trait("Category", "OnTarget")]
public sealed class LiveDiagnosticsTests(ITestOutputHelper output)
{
    [Fact]
    public void System_overview_reports_a_plausible_machine()
    {
        var overview = new WindowsSystemInspector(new WindowsPrivilegeProbe()).Describe();

        output.WriteLine($"{overview.MachineName}: {overview.OperatingSystem}, up {overview.Uptime}");

        Assert.NotEmpty(overview.MachineName);
        Assert.True(overview.ProcessorCount > 0);
        Assert.True(overview.TotalPhysicalMemoryBytes > 0, "physical memory came back as zero");
        Assert.True(overview.AvailablePhysicalMemoryBytes <= overview.TotalPhysicalMemoryBytes);
        Assert.True(overview.Uptime > TimeSpan.Zero);
        Assert.NotEmpty(overview.Disks);
    }

    [Fact]
    public void Process_list_finds_this_test_process_with_its_command_line()
    {
        var inspector = new WmiProcessInspector(new WinDiagOptions(), NullLogger<WmiProcessInspector>.Instance);

        var result = inspector.List(null, Environment.ProcessId, CancellationToken.None);

        var self = Assert.Single(result.Processes);
        Assert.Equal(Environment.ProcessId, self.ProcessId);
        Assert.NotNull(self.ParentProcessId);

        // Our own command line is always readable, so a null here means WMI enrichment is broken
        // rather than that permissions got in the way.
        Assert.NotNull(self.CommandLine);
        output.WriteLine(self.CommandLine);
    }

    [Fact]
    public void Service_config_reads_a_service_present_on_every_windows_machine()
    {
        var result = new WindowsServiceInspector().Query("Winmgmt", CancellationToken.None);

        var service = result.Service;
        Assert.NotNull(service);
        output.WriteLine($"{service.ServiceName}: {service.Status}, {service.StartType}, {service.Account}");

        Assert.Equal("Winmgmt", service.ServiceName);
        Assert.NotNull(service.ImagePath);
        Assert.NotNull(service.Account);
        Assert.NotEqual("(unknown)", service.StartType);
    }

    [Fact]
    public void Service_config_finds_a_kernel_driver_not_just_a_win32_service()
    {
        // Drivers are enumerated by GetDevices(), not GetServices(). Querying only the latter makes
        // every driver answer "no such service exists" -- and driver-failed-to-load is one of the most
        // common things anyone points this tool at.
        var result = new WindowsServiceInspector().Query("Tcpip", CancellationToken.None);

        Assert.NotNull(result.Service);
        output.WriteLine($"{result.Service.ServiceName}: {result.Service.Status}, " +
                         $"{result.Service.StartType}, type={result.Service.ServiceType}");

        Assert.Contains("Driver", result.Service.ServiceType, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Event_log_tail_returns_information_records_including_level_zero()
    {
        var levels = Tools.EventLogTools.ParseLevels(["information"]);

        var result = new WindowsEventLogInspector().Query(
            "Application", 60 * 24 * 30, levels, null, [], 50, CancellationToken.None);

        output.WriteLine($"{result.Events.Count} information records over 30 days");

        // A month of the Application log at Information on any real machine is never empty. If it is,
        // the level filter is dropping records rather than the machine being quiet.
        Assert.NotEmpty(result.Events);
    }

    [Fact]
    public void Service_lookup_suggests_alternatives_for_a_partial_name()
    {
        var result = new WindowsServiceInspector().Query("Winmgm", CancellationToken.None);

        Assert.Null(result.Service);
        Assert.Contains(result.Candidates, c => c.StartsWith("Winmgmt", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Event_log_tail_reads_the_system_log()
    {
        // A week of any severity: even a freshly imaged machine logs boot events.
        var result = new WindowsEventLogInspector().Query(
            "System", 60 * 24 * 7, [], null, [], 20, CancellationToken.None);

        output.WriteLine($"{result.Events.Count} records");

        Assert.NotEmpty(result.Events);
        Assert.All(result.Events, e => Assert.NotEmpty(e.Provider));
        Assert.All(result.Events, e => Assert.True(e.TimeCreated > DateTimeOffset.UnixEpoch));
    }

    [Fact]
    public void Event_log_tail_suggests_alternatives_for_a_log_that_does_not_exist()
    {
        var result = new WindowsEventLogInspector().Query(
            "Sytsem", 60, [], null, [], 10, CancellationToken.None);

        Assert.Empty(result.Events);
        Assert.NotEmpty(result.Candidates);
    }

    [Fact]
    public void Effective_access_probes_a_file_this_test_created()
    {
        var path = Path.Combine(Path.GetTempPath(), $"windiag-acl-{Guid.NewGuid():N}.txt");
        File.WriteAllText(path, "probe me");

        try
        {
            var report = new WindowsAccessInspector().Inspect(path, null, probeWrite: true, CancellationToken.None);

            output.WriteLine($"owner={report.Owner}, rules={report.Rules.Count}");

            Assert.Equal(SecurableKind.File, report.Kind);
            Assert.NotNull(report.Owner);
            Assert.NotEmpty(report.Rules);

            // We just created it, so both must succeed. If either comes back denied the probe is wrong.
            Assert.True(report.Probe.CanRead);
            Assert.True(report.Probe.CanWrite);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Effective_access_reports_denial_empirically_rather_than_only_from_the_acl()
    {
        // A file held exclusively cannot be opened, and no ACE explains that. This is exactly the case
        // where an ACL-only tool says "you have access" and the user still sees a failure.
        var path = Path.Combine(Path.GetTempPath(), $"windiag-locked-{Guid.NewGuid():N}.txt");

        using (new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
        {
            var report = new WindowsAccessInspector().Inspect(path, null, probeWrite: false, CancellationToken.None);

            Assert.False(report.Probe.CanRead);
            Assert.NotNull(report.Probe.ReadError);
            output.WriteLine(report.Probe.ReadError);

            // The ACL still grants access; only the probe reveals the real answer.
            Assert.NotEmpty(report.Rules);
        }

        File.Delete(path);
    }

    [Fact]
    public void Effective_access_reads_a_registry_key()
    {
        var report = new WindowsAccessInspector().Inspect(
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "Administrators", false, CancellationToken.None);

        Assert.Equal(SecurableKind.RegistryKey, report.Kind);
        Assert.NotEmpty(report.Rules);
        Assert.Contains(report.Rules, r => r.Rights.Contains("Read", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Registry_paths_are_recognised_and_split_by_hive()
    {
        Assert.True(WindowsAccessInspector.IsRegistryPath(@"HKLM\SOFTWARE"));
        Assert.True(WindowsAccessInspector.IsRegistryPath(@"HKEY_CURRENT_USER\Console"));
        Assert.False(WindowsAccessInspector.IsRegistryPath(@"C:\Windows"));

        var (hive, subKey) = WindowsAccessInspector.SplitRegistryPath(@"HKLM\SOFTWARE\Vendor");
        Assert.Equal(Microsoft.Win32.RegistryHive.LocalMachine, hive);
        Assert.Equal(@"SOFTWARE\Vendor", subKey);
    }
}
