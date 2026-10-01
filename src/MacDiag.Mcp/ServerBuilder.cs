using Diag.Mcp.Server.Commands;
using Diag.Mcp.Server.Files;
using Diag.Mcp.Server.SelfUpdate;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Diagnostics;
using MacDiag.Mcp.Diagnostics.Capabilities;
using MacDiag.Mcp.Diagnostics.Commands;
using MacDiag.Mcp.Diagnostics.Handles;
using MacDiag.Mcp.Diagnostics.Processes;
using MacDiag.Mcp.Diagnostics.SystemInfo;
using MacDiag.Mcp.Mac;
using MacDiag.Mcp.Tools;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace MacDiag.Mcp;

/// <summary>Wires the macOS server: the kit's shared surface, then this server's own tools and grants.</summary>
public static class ServerBuilder
{
    public const string HelpText = """
        macdiag - macOS diagnostics MCP server

        Usage:
          MacDiag.Mcp                            serve MCP over stdio
          MacDiag.Mcp --http <url>               serve MCP over HTTP, e.g. --http http://0.0.0.0:4025
          MacDiag.Mcp --env-file <path>          read MACDIAG_* settings from a root:wheel 0600 file first;
                                                 the server refuses to start if another account could
                                                 have written it or any directory above it
          MacDiag.Mcp --help                     this text

        Service management (root; launchd):
          MacDiag.Mcp --install-service --http <url> [--token-stdin | --token <t>] [--label <l>] [--artifacts <dir>]
                      [--allow-self-update] [--allow-command-execution] [--allow-arbitrary-write]
                      [--allow-arbitrary-read] [--read-only]
          MacDiag.Mcp --uninstall-service [--label <l>] [--purge]
          MacDiag.Mcp --service-status [--label <l>]
        Installs /Library/PrivilegedHelperTools/com.windiag.macdiag/MacDiag.Mcp, /etc/macdiag/<l>.env
        (0600: token and grants), /var/db/macdiag and /var/log/macdiag (0700) and
        /Library/LaunchDaemons/<l>.plist (default label com.windiag.macdiag), then loads it and waits until
        the new job is the process listening, reporting the Application Firewall's state. An existing
        --artifacts directory is used only if root alone can write it, and is never re-chmodded. --token-stdin reads the token from
        standard input, keeping it out of sudo's log and ps. --purge also deletes /var/db/macdiag.
        Under launchd the server logs to /var/log/macdiag/macdiag.log (rolled at 10 MiB); crash.log holds
        what the runtime writes before that, including a refused configuration, which launchd retries
        every 10 s until it is fixed.

        put_file writes freely only under the artifact directory. Into the server's own directory it
        needs MACDIAG_ALLOW_SELF_UPDATE=1, since staging a build is the only reason to.

        Configuration (environment, or the --env-file, which wins):
          MACDIAG_HTTP_BIND                      address to serve on when --http has none
          MACDIAG_TOKEN                          bearer token; generated and printed once when unset
          MACDIAG_READ_ONLY=1                    register no tool that changes the machine
          MACDIAG_ALLOW_SELF_UPDATE=1            let put_file write into the server's own directory
                                                 to stage a build
          MACDIAG_ALLOW_COMMAND_EXECUTION=1      register run_command
          MACDIAG_ALLOW_ARBITRARY_WRITE=1        let put_file write anywhere, the server's own directory included
          MACDIAG_ALLOW_ARBITRARY_READ=1         let get_file read outside the server's directories
          MACDIAG_ARTIFACT_DIR                   default /var/db/macdiag
          MACDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS  default 120 (1..3600)
          MACDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS   default 1800 (1..86400)
          MACDIAG_MAX_RESULTS                    default 50000
          MACDIAG_SERVICE_LABEL                  the launchd label; written by --install-service
          MACDIAG_PROTECTED_LABELS               extra launchd labels, comma-separated, that service
                                                 control refuses to stop

        The channel is plaintext HTTP. Never route it across a network you do not trust.
        """;

    public static IMcpServerBuilder ConfigureServices(IServiceCollection services, MacDiagOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        services.AddSingleton(options);
        services.TryAddSingleton(new CommandRunnerOptions(options.ExternalToolTimeout));

        TryAddDiagnostics(services);

        // The install directory holds a root daemon's binary, so put_file writes there only to stage a build,
        // and only with that grant.
        var files = new FileTransferOptions(
            options.ArtifactDirectory, options.AllowArbitraryWrite, options.AllowArbitraryRead,
            "MACDIAG_ALLOW_ARBITRARY_WRITE=1", "MACDIAG_ALLOW_ARBITRARY_READ=1",
            ServerDirectoryWritable: options.AllowSelfUpdate,
            ServerDirectorySetting: "MACDIAG_ALLOW_SELF_UPDATE=1");
        var update = new SelfUpdateOptions(options.ArtifactDirectory, options.UpdateDrainTimeout);

        var mcp = services.AddDiagServer(new DiagServerSettings(options.ReadOnly, files, update), out _)
            .WithTools<SystemTools>(DiagServerKit.ToolJsonOptions)
            .WithTools<ProcessTools>(DiagServerKit.ToolJsonOptions)
            .WithTools<HandleTools>(DiagServerKit.ToolJsonOptions)
            .WithTools<ModuleTools>(DiagServerKit.ToolJsonOptions)
            .WithTools<LockTools>(DiagServerKit.ToolJsonOptions);

        // The heaviest grant: the bearer token becomes arbitrary code execution as root. Its own flag,
        // refused under read-only -- the same rule every server keeps.
        if (options.AllowCommandExecution && !options.ReadOnly)
        {
            mcp.WithTools<CommandTools>(DiagServerKit.ToolJsonOptions);
        }

        return mcp;
    }

    /// <summary>This server's implementations, each added only if a test has not registered its own.</summary>
    internal static void TryAddDiagnostics(IServiceCollection services)
    {
        services.TryAddSingleton<IPrivilegeProbe, MacPrivilegeProbe>();
        services.TryAddSingleton<IExternalCommand, MacSystemCommand>();
        services.TryAddSingleton<IExecutableResolver>(new SystemExecutableResolver(MacSystemCommand.SystemDirectories));
        services.TryAddSingleton<ICapabilityRequirements, MacCapabilityRequirements>();
        services.TryAddSingleton<ICapabilityReporter, CapabilityReporter>();
        services.TryAddSingleton<ISystemInspector, MacSystemInspector>();
        services.TryAddSingleton<SystemTools>();
        services.TryAddSingleton<IProcessTable, MacProcessTable>();
        services.TryAddSingleton<ProcessTools>();
        services.TryAddSingleton<IHandleInspector, MacHandleInspector>();
        services.TryAddSingleton<IModuleInspector, MacModuleInspector>();
        services.TryAddSingleton<HandleTools>();
        services.TryAddSingleton<ModuleTools>();
        services.TryAddSingleton<ILockInspector, MacLockInspector>();
        services.TryAddSingleton<LockTools>();
        services.TryAddSingleton<IShellSet, MacShellSet>();
        services.TryAddSingleton<ICommandRunner, CommandRunner>();
        services.TryAddSingleton<CommandTools>();
    }
}
