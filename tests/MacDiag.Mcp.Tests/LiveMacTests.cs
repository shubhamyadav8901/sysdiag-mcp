using System.Collections;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics;
using MacDiag.Mcp.Diagnostics.Handles;
using MacDiag.Mcp.Diagnostics.Network;
using MacDiag.Mcp.Diagnostics.Processes;
using MacDiag.Mcp.Mac;

namespace MacDiag.Mcp.Tests;

/// <summary>Each test makes its own evidence on a real Mac and asks a tool to find it; CI's macos-latest job runs them.</summary>
/// <remarks>
/// These are what settle the assumptions the parsers were written on without a Mac: lsof's and ps's escaping in the
/// C locale, socket grouping, and the /private and firmlink spellings.
/// </remarks>
[SupportedOSPlatform("macos")]
public sealed class LiveMacTests : IDisposable
{
    private static readonly MacDiagOptions Options = MacDiagOptions.FromEnvironment(new Hashtable());
    private readonly string _root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"live-{Guid.NewGuid():N}")).FullName;
    private readonly List<Process> _children = [];
    private readonly List<int> _orphans = [];

    public void Dispose()
    {
        foreach (var child in _children)
        {
            try
            {
                child.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }

            child.Dispose();
        }

        foreach (var orphan in _orphans)
        {
            try
            {
                using var process = Process.GetProcessById(orphan);
                process.Kill();
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            {
                // Already gone: the test terminated it.
            }
        }

        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private static MacSystemCommand Commands => new();

    [MacFact]
    public async Task An_open_file_with_a_non_ascii_name_is_listed_decoded_and_found_under_both_spellings()
    {
        var path = Path.Combine(_root, "café ünïcode.txt");
        await using var held = new FileStream(path, FileMode.Create);
        var handles = new MacHandleInspector(Commands, new MacPrivilegeProbe(), Options);

        var mine = await handles.ForProcessAsync(Environment.ProcessId, includeAllObjectTypes: false, CancellationToken.None);
        Assert.Contains(mine.Entries, e => e.Name.EndsWith("café ünïcode.txt", StringComparison.Ordinal));

        // TMPDIR is /var/folders/...; the kernel reports /private/var/folders/... -- both must find it.
        foreach (var spelling in PathSpellings.Of(path, PathSpellings.SystemFirmlinks).Where(s => !s.StartsWith("/System/Volumes/Data", StringComparison.Ordinal)))
        {
            var found = await handles.SearchAsync(spelling, includeAllObjectTypes: false, CancellationToken.None);
            Assert.Contains(found.Entries, e => e.ProcessId == Environment.ProcessId);
        }
    }

    [MacFact]
    public async Task A_listening_socket_is_owned_by_this_process_and_reads_as_listen()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var result = await new MacNetworkInspector(Commands, Options).EndpointsAsync(port, null, listeningOnly: true, CancellationToken.None);

        var endpoint = Assert.Single(result.Endpoints);
        Assert.Equal("Listen", endpoint.State);
        Assert.Contains(endpoint.Owners, o => o.ProcessId == Environment.ProcessId);
    }

    [MacFact]
    public async Task A_bound_unix_socket_and_a_held_fifo_are_listed_by_name()
    {
        var socketPath = Path.Combine(_root, "live.sock");
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        socket.Bind(new UnixDomainSocketEndPoint(socketPath));
        socket.Listen();

        var fifo = Path.Combine(_root, "live.fifo");
        Process.Start("/usr/bin/mkfifo", [fifo])!.WaitForExit();
        // Opened read-write in a child, which does not block waiting for a writer.
        _children.Add(Process.Start("/bin/sh", ["-c", "exec 3<> \"$0\"; sleep 30", fifo])!);
        await Task.Delay(500);

        var pipes = await new MacPipeInspector(Commands, Options).ListAsync("live", CancellationToken.None);

        Assert.Contains(pipes.Pipes, p => p.Kind == "UnixSocket" && p.Name.EndsWith("live.sock", StringComparison.Ordinal));
        Assert.Contains(pipes.Pipes, p => p.Kind == "Fifo" && p.Name.EndsWith("live.fifo", StringComparison.Ordinal));
    }

    [MacFact]
    public async Task A_line_written_with_logger_is_found_by_event_log_tail()
    {
        var marker = $"macdiag-live-{Guid.NewGuid():N}";
        Process.Start("/usr/bin/logger", ["-t", "macdiag-live", marker])!.WaitForExit();
        var log = new Diagnostics.Log.MacLogInspector(Commands, Options);

        // The unified log is asynchronous: give the line a few seconds to land.
        for (var attempt = 0; attempt < 10; attempt++)
        {
            var result = await log.QueryAsync("logger", null, null, null, 5, ["all"], 50, CancellationToken.None);
            if (result.Events.Any(e => e.Message?.Contains(marker, StringComparison.Ordinal) == true))
            {
                return;
            }

            await Task.Delay(1000);
        }

        Assert.Fail($"{marker} never appeared in event_log_tail");
    }

    [MacFact]
    public async Task Remote_logins_job_is_described_from_its_plist_whose_name_is_not_its_label()
    {
        var result = await new Diagnostics.Services.MacServiceInspector(Commands, Options).QueryAsync("com.openssh.sshd", CancellationToken.None);

        Assert.NotNull(result.Service);
        Assert.EndsWith("ssh.plist", result.Service.PlistPath, StringComparison.Ordinal);
        Assert.NotNull(result.Service.Program);
    }

    [MacFact]
    public async Task A_spawned_process_is_suspended_resumed_and_terminated_and_a_wrong_name_is_refused()
    {
        var controller = new Diagnostics.Control.MacProcessController(Commands, Options, Microsoft.Extensions.Logging.Abstractions.NullLogger<Diagnostics.Control.MacProcessController>.Instance);

        // Stopping this process's own child would wedge it (see MacProcessController), so that is refused, and the
        // process that is suspended is an orphan launchd has adopted.
        var child = Process.Start("/bin/sleep", ["60"])!;
        _children.Add(child);
        var refused = await Assert.ThrowsAsync<Diagnostics.Control.ProcessControlException>(() =>
            controller.ControlAsync(child.Id, "sleep", Diagnostics.Control.ProcessAction.Suspend, null, CancellationToken.None));
        Assert.Contains("child of this server", refused.Message, StringComparison.Ordinal);

        var pid = await StartOrphanSleepAsync();
        var pidText = pid.ToString(System.Globalization.CultureInfo.InvariantCulture);

        async Task<string> State() =>
            (await Commands.RunAsync("ps", ["-p", pidText, "-o", "stat="], TimeSpan.FromSeconds(10), CancellationToken.None)).StandardOutput.Trim();

        await Assert.ThrowsAsync<Diagnostics.Control.ProcessControlException>(() =>
            controller.ControlAsync(pid, "nginx", Diagnostics.Control.ProcessAction.Kill, null, CancellationToken.None));
        Assert.NotEmpty(await State());

        await controller.ControlAsync(pid, "sleep", Diagnostics.Control.ProcessAction.Suspend, null, CancellationToken.None);
        Assert.Contains("T", await State(), StringComparison.Ordinal);

        await controller.ControlAsync(pid, "sleep", Diagnostics.Control.ProcessAction.Resume, null, CancellationToken.None);
        Assert.DoesNotContain("T", await State(), StringComparison.Ordinal);

        var terminated = await controller.ControlAsync(pid, "sleep", Diagnostics.Control.ProcessAction.Terminate, null, CancellationToken.None);
        Assert.Contains("Exited", terminated.Detail, StringComparison.Ordinal);
    }

    /// <summary>A sleep whose shell has exited, so its parent is launchd rather than this process.</summary>
    private async Task<int> StartOrphanSleepAsync()
    {
        // The sleep's output goes to /dev/null: holding the shell's pipe open, it would keep ReadToEnd waiting for 60 s.
        using var shell = Process.Start(new ProcessStartInfo("/bin/sh", ["-c", "sleep 60 </dev/null >/dev/null 2>&1 & echo $!"])
        {
            RedirectStandardOutput = true,
        })!;
        var pid = int.Parse((await shell.StandardOutput.ReadToEndAsync()).Trim(), System.Globalization.CultureInfo.InvariantCulture);
        await shell.WaitForExitAsync();
        _orphans.Add(pid);
        return pid;
    }

    [MacFact]
    public async Task Stopping_the_window_server_is_refused_before_launchctl_is_asked_anything()
    {
        var controller = new Diagnostics.Services.MacServiceController(Commands, Options, Microsoft.Extensions.Logging.Abstractions.NullLogger<Diagnostics.Services.MacServiceController>.Instance);

        await Assert.ThrowsAsync<Diagnostics.Services.ServiceControlException>(() =>
            controller.ControlAsync("com.apple.WindowServer", Diagnostics.Services.ServiceAction.Stop, CancellationToken.None));
    }

    [MacFact]
    public async Task A_command_line_with_spaces_and_non_ascii_comes_back_as_it_was_given()
    {
        // "; :" keeps the shell alive: a lone command after -c is exec'd, and the PID would become sleep's.
        var child = Process.Start("/bin/sh", ["-c", "sleep 30; :", "arg with space café", "-Dre=\\d+\\s", "^[a-z]M-C\tend"])!;
        _children.Add(child);
        await Task.Delay(500);

        var table = await new MacProcessTable(Commands, Options).ReadAsync(CancellationToken.None);

        var row = table.Processes.Single(p => p.ProcessId == child.Id);
        Assert.Contains("arg with space café", row.CommandLine, StringComparison.Ordinal);
        Assert.Contains("-Dre=\\d+\\s", row.CommandLine, StringComparison.Ordinal);
        // Text that looks like ps's unmarked escapes is text; a real tab comes back as one.
        Assert.Contains("^[a-z]M-C\tend", row.CommandLine, StringComparison.Ordinal);
        // /bin/sh hands over to the selected shell, so comm may name bash, zsh or sh: only its shape is certain.
        Assert.NotNull(row.ExecutablePath);
        Assert.StartsWith("/", row.ExecutablePath, StringComparison.Ordinal);
        Assert.EndsWith("sh", row.ExecutablePath, StringComparison.Ordinal);
    }

    [MacFact]
    public async Task A_developer_id_binary_is_valid_with_its_team_because_apple_issued_its_certificate()
    {
        // The dotnet host running this test is signed with Microsoft's Developer ID here and on CI. Run against the real
        // codesign, this is what proves "-R=anchor apple generic" is a requirement it accepts: a malformed one would exit
        // neither 0 nor 3, and every Developer ID file would read as Unknown.
        var host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } dotnet ? dotnet : Environment.ProcessPath!;

        var file = Assert.Single((await new Diagnostics.Signatures.MacSignatureInspector(Commands, Options).InspectAsync([host], CancellationToken.None)).Files);

        Assert.Equal(Diagnostics.Signatures.SignatureVerdict.Valid, file.Verdict);
        Assert.StartsWith("Developer ID Application: ", file.Authorities[0], StringComparison.Ordinal);
        Assert.Equal($"Signed by certificate \"{file.Authorities[0]}\" (team {file.TeamId}), verified", file.Detail);
    }

    [MacFact]
    public async Task A_platform_binary_is_signed_by_apple_and_a_bare_tool_has_no_gatekeeper_assessment()
    {
        var result = await new Diagnostics.Signatures.MacSignatureInspector(Commands, Options).InspectAsync(["/bin/ls"], CancellationToken.None);

        var ls = Assert.Single(result.Files);
        Assert.Equal(Diagnostics.Signatures.SignatureVerdict.Valid, ls.Verdict);
        Assert.Equal("Signed by Apple, verified", ls.Detail);
        Assert.Equal("not applicable", ls.Gatekeeper);
        Assert.Equal(64, ls.Sha256.Length);
    }

    [MacFact]
    public async Task A_file_nobody_signed_is_unsigned_and_a_fifo_returns_at_once_as_not_a_regular_file()
    {
        var plain = Path.Combine(_root, "plain.txt");
        await File.WriteAllTextAsync(plain, "hello");
        var fifo = Path.Combine(_root, "pipe");
        using (var mkfifo = Process.Start("/usr/bin/mkfifo", [fifo])!)
        {
            await mkfifo.WaitForExitAsync();
        }

        var watch = Stopwatch.StartNew();
        var result = await new Diagnostics.Signatures.MacSignatureInspector(Commands, Options).InspectAsync([plain, fifo], CancellationToken.None);

        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(30), $"took {watch.Elapsed}");
        Assert.Equal(Diagnostics.Signatures.SignatureVerdict.Unsigned, Assert.Single(result.Files).Verdict);
        Assert.Contains(result.NotFound, n => n.EndsWith("(not a regular file)", StringComparison.Ordinal));
    }

    [MacFact]
    public async Task The_kernel_says_the_owner_of_a_0600_file_may_read_and_write_it_but_not_execute_it()
    {
        var file = Path.Combine(_root, "private.txt");
        await File.WriteAllTextAsync(file, "x");
        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        var report = await new Diagnostics.Access.MacAccessInspector(Commands, Options).InspectAsync(file, Environment.UserName, null, CancellationToken.None);

        Assert.Equal((true, true, false), (report.Read.Allowed, report.Write.Allowed, report.Execute.Allowed));
        Assert.True(report.Probe.SameSubject);
        Assert.Null(report.BlockedAt);
        Assert.NotNull(report.MountPoint);
    }

    [MacFact]
    public async Task Apples_own_daemons_show_only_when_asked_for()
    {
        var inspector = new Diagnostics.Autostart.MacAutostartInspector(Commands, Options, new MacPrivilegeProbe());

        var all = await inspector.AuditAsync(new Diagnostics.Autostart.AutostartQuery("daemons", HideApple: false), CancellationToken.None);
        var hidden = await inspector.AuditAsync(new Diagnostics.Autostart.AutostartQuery("daemons"), CancellationToken.None);

        Assert.Contains(all.Entries, e => e.Entry.StartsWith("com.apple.", StringComparison.Ordinal));
        Assert.DoesNotContain(hidden.Entries, e => e.Location.StartsWith("/System/", StringComparison.Ordinal));
    }

    [MacFact]
    public async Task System_and_kernel_extensions_are_read_without_an_unrecognised_output_limitation()
    {
        var inspector = new Diagnostics.Autostart.MacAutostartInspector(Commands, Options, new MacPrivilegeProbe());

        var result = await inspector.AuditAsync(new Diagnostics.Autostart.AutostartQuery("sysext,kext", HideApple: false), CancellationToken.None);

        Assert.DoesNotContain(result.Limitations, l => l.Contains("recognises", StringComparison.Ordinal));
        Assert.Contains(result.Entries, e => e.Category == "kext");
    }

    [MacFact]
    public async Task With_no_container_engine_running_the_list_is_empty_and_no_socket_was_refused()
    {
        var catalog = await new Diagnostics.Containers.MacContainerInspector(Commands, Options, new Diagnostics.Containers.MacDockerClient(), new MacPrivilegeProbe())
            .ListAsync(CancellationToken.None);

        Assert.DoesNotContain(catalog.Limitations, l => l.StartsWith("Not asking", StringComparison.Ordinal));
    }
}
