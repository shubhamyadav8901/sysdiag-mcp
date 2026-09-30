using Diag.Mcp.Server.Commands;
using Diag.Mcp.Server.Files;
using Diag.Mcp.Server.SelfUpdate;
using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Diagnostics;
using LinuxDiag.Mcp.Diagnostics.Capabilities;
using LinuxDiag.Mcp.Diagnostics.Commands;
using LinuxDiag.Mcp.Diagnostics.SelfUpdate;
using LinuxDiag.Mcp.Diagnostics.SystemInfo;
using LinuxDiag.Mcp.Tools;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace LinuxDiag.Mcp;

/// <summary>Wires the Linux server: the kit's shared surface, then this server's own tools and grants.</summary>
public static class ServerBuilder
{
    public const string HelpText = """
        linuxdiag - Linux diagnostics MCP server

        Usage:
          LinuxDiag.Mcp                          serve MCP over stdio
          LinuxDiag.Mcp --http <url>             serve MCP over HTTP, e.g. --http http://0.0.0.0:4024
          LinuxDiag.Mcp --help                   this text

        Service management (root; systemd):
          LinuxDiag.Mcp --install-service --http <url> [--token-stdin | --token <t>] [--service-name <n>] [--artifacts <dir>]
                        [--allow-self-update] [--allow-command-execution] [--allow-arbitrary-write]
                        [--allow-arbitrary-read] [--read-only] [--no-restart-on-failure]
          LinuxDiag.Mcp --uninstall-service [--service-name <n>]
          LinuxDiag.Mcp --service-status [--service-name <n>]
        Installs /opt/linuxdiag/LinuxDiag.Mcp, /etc/linuxdiag/<n>.env (0600: token and grants),
        /var/lib/linuxdiag (0700) and /etc/systemd/system/<n>.service, then enables and starts it.
        --token-stdin reads the token from standard input, keeping it out of sudo's log and ps.

        Configuration (environment):
          LINUXDIAG_HTTP_BIND                    address to serve on when --http has none
          LINUXDIAG_TOKEN                        bearer token; generated and printed once when unset
          LINUXDIAG_READ_ONLY=1                  register no tool that changes the machine
          LINUXDIAG_ALLOW_SELF_UPDATE=1          register update_self
          LINUXDIAG_ALLOW_COMMAND_EXECUTION=1    register run_command
          LINUXDIAG_ALLOW_ARBITRARY_WRITE=1      let put_file write outside the server's directories
          LINUXDIAG_ALLOW_ARBITRARY_READ=1       let get_file read outside the server's directories
          LINUXDIAG_ARTIFACT_DIR                 default /var/lib/linuxdiag
          LINUXDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS  default 120 (1..3600)
          LINUXDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS   default 1800 (1..86400)
          LINUXDIAG_MAX_RESULTS                  default 50000
          LINUXDIAG_SERVICE_NAME                 the systemd unit; written by --install-service

        The channel is plaintext HTTP. Never route it across a network you do not trust.
        """;

    public static IMcpServerBuilder ConfigureServices(IServiceCollection services, LinuxDiagOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        services.AddSingleton(options);
        services.TryAddSingleton(new CommandRunnerOptions(options.ExternalToolTimeout));

        // Inert unless systemd started this process. Under it, the host reports ready through sd_notify
        // (the unit is Type=notify, so `systemctl start` returns once the server is really listening)
        // and logs in the format journald understands.
        services.AddSystemd();

        TryAddDiagnostics(services);

        var files = new FileTransferOptions(
            options.ArtifactDirectory, options.AllowArbitraryWrite, options.AllowArbitraryRead,
            "LINUXDIAG_ALLOW_ARBITRARY_WRITE=1", "LINUXDIAG_ALLOW_ARBITRARY_READ=1");
        var update = new SelfUpdateOptions(options.ArtifactDirectory, options.UpdateDrainTimeout);

        var mcp = services.AddDiagServer(new DiagServerSettings(options.ReadOnly, files, update), out _)
            .WithTools<SystemTools>(DiagServerKit.ToolJsonOptions);

        // The heaviest grant: the bearer token becomes arbitrary code execution as root. Its own flag,
        // refused under read-only -- the same rule every server keeps, pinned by GatedToolGuard.
        if (options.AllowCommandExecution && !options.ReadOnly)
        {
            mcp.WithTools<CommandTools>(DiagServerKit.ToolJsonOptions);
        }

        // Lets the token replace the root-owned binary and run it: its own grant, refused under read-only.
        if (options.AllowSelfUpdate && !options.ReadOnly)
        {
            mcp.WithTools<SelfUpdateTools>(DiagServerKit.ToolJsonOptions);
        }

        return mcp;
    }

    /// <summary>This server's implementations, each added only if a test has not registered its own.</summary>
    internal static void TryAddDiagnostics(IServiceCollection services)
    {
        services.TryAddSingleton<IPrivilegeProbe, LinuxPrivilegeProbe>();
        services.TryAddSingleton<IExecutableResolver, PathExecutableResolver>();
        services.TryAddSingleton<ICapabilityRequirements, LinuxCapabilityRequirements>();
        services.TryAddSingleton<ICapabilityReporter, CapabilityReporter>();
        services.TryAddSingleton<ISystemInspector, LinuxSystemInspector>();
        services.TryAddSingleton<SystemTools>();
        services.TryAddSingleton<IShellSet, LinuxShellSet>();
        services.TryAddSingleton<ICommandRunner, CommandRunner>();
        services.TryAddSingleton<CommandTools>();
        services.TryAddSingleton<IStagedBuildInspector, LinuxStagedBuildInspector>();
        services.TryAddSingleton<IUpdateGuard, ElfUpdateGuard>();
        services.TryAddSingleton<IRestartHelper, SystemdRestartHelper>();
        services.TryAddSingleton<ISelfUpdater, SelfUpdater>();
        services.TryAddSingleton<SelfUpdateTools>();
    }
}
