using Diag.Mcp.Server.SelfUpdate;
using LinuxDiag.Mcp.Diagnostics.SelfUpdate;

namespace LinuxDiag.Mcp.Tests;

public sealed class ElfHeaderTests
{
    /// <summary>The first 20 bytes of an x86-64 ELF executable (ET_DYN, as a .NET apphost is).</summary>
    private static byte[] X64Elf() =>
        [0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0x3E, 0];

    [Fact]
    public void An_x64_linux_executable_is_accepted() => Assert.Null(ElfHeader.Problem(X64Elf()));

    [Fact]
    public void A_windows_exe_staged_by_mistake_is_refused()
    {
        byte[] mz = [(byte)'M', (byte)'Z', 0x90, 0, .. new byte[16]];

        Assert.Contains("not a Linux executable", ElfHeader.Problem(mz), StringComparison.Ordinal);
    }

    [Fact]
    public void An_arm64_build_is_refused_by_name()
    {
        var arm = X64Elf();
        arm[18] = 0xB7; // EM_AARCH64

        Assert.Contains("x86-64", ElfHeader.Problem(arm), StringComparison.Ordinal);
    }

    [Fact]
    public void A_truncated_file_is_refused() =>
        Assert.NotNull(ElfHeader.Problem([0x7F, (byte)'E']));

    [LinuxFact]
    public void The_running_test_host_passes_and_a_text_file_does_not()
    {
        var guard = new ElfUpdateGuard();
        guard.RequireAcceptable("/x", new StagedBuild(Environment.ProcessPath!, "", 0, "NotSigned", null), CancellationToken.None);

        var text = Path.Combine(Path.GetTempPath(), $"ld-{Guid.NewGuid():N}.txt");
        File.WriteAllText(text, "#!/bin/sh\necho not a build\n");
        try
        {
            Assert.Throws<SelfUpdateRejectedException>(() => guard.RequireAcceptable(
                "/x", new StagedBuild(text, "", 0, "NotSigned", null), CancellationToken.None));
        }
        finally
        {
            File.Delete(text);
        }
    }
}

public sealed class RestartScriptTests
{
    [Fact]
    public void The_script_waits_rechecks_the_hash_then_swaps_then_restarts()
    {
        var script = SystemdRestartHelper.Script(
            4242, "/opt/linuxdiag/LinuxDiag.Mcp", "/opt/linuxdiag/LinuxDiag.Mcp.new", "ABC",
            "/var/lib/linuxdiag/self-update.log", "systemctl restart 'linuxdiag'");

        var wait = script.IndexOf("kill -0 4242", StringComparison.Ordinal);
        var check = script.IndexOf("sha256sum", StringComparison.Ordinal);
        var move = script.IndexOf("mv -f", StringComparison.Ordinal);

        Assert.True(wait >= 0 && wait < check && check < move, "the hash must be re-checked after the exit and before the swap");
        Assert.Contains("'ABC'", script, StringComparison.Ordinal);
        Assert.Contains("chmod 0755", script, StringComparison.Ordinal);
    }

    [Fact]
    public void A_service_restarts_through_systemctl_and_a_by_hand_run_relaunches_itself()
    {
        Assert.Equal("systemctl restart 'linuxdiag'",
            SystemdRestartHelper.RestartCommand(underSystemd: true, "linuxdiag", "/opt/x", ["--http", "http://0.0.0.0:4024"]));
        Assert.StartsWith("setsid '/opt/x' '--http' 'http://0.0.0.0:4024'",
            SystemdRestartHelper.RestartCommand(underSystemd: false, null, "/opt/x", ["--http", "http://0.0.0.0:4024"]), StringComparison.Ordinal);
    }

    [Fact]
    public void A_by_hand_run_with_the_service_name_set_relaunches_itself_rather_than_restarting_the_service()
    {
        // The launch and the restart must agree on "under systemd". Deciding the restart from the service
        // name alone made a by-hand run, started with LINUXDIAG_SERVICE_NAME in its environment,
        // restart the installed service instead of bringing itself back.
        Assert.False(SystemdRestartHelper.UnderSystemd("linuxdiag", invocationId: null));
        Assert.False(SystemdRestartHelper.UnderSystemd(null, invocationId: "abc"));
        Assert.True(SystemdRestartHelper.UnderSystemd("linuxdiag", invocationId: "abc"));
    }

    [Fact]
    public void A_single_quote_in_a_path_is_refused_before_anything_is_written()
    {
        // Review Focus 5: a quote would end the shell string mid-path and the helper would run whatever
        // followed. Refused up front, while the server is still running and nothing has been launched.
        Assert.Throws<SelfUpdateRejectedException>(() => SystemdRestartHelper.ShellQuote("/opt/it's/LinuxDiag.Mcp"));
    }
}
