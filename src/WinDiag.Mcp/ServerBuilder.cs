using System.Text.Json;
using System.Text.Json.Serialization;
using Diag.Mcp.Server.Commands;
using Diag.Mcp.Server.Files;
using Diag.Mcp.Server.SelfUpdate;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.Access;
using WinDiag.Mcp.Diagnostics.Activity;
using WinDiag.Mcp.Diagnostics.Autostart;
using WinDiag.Mcp.Diagnostics.Capabilities;
using WinDiag.Mcp.Diagnostics.Commands;
using WinDiag.Mcp.Diagnostics.Dumps;
using WinDiag.Mcp.Diagnostics.EventLogs;
using WinDiag.Mcp.Diagnostics.External;
using WinDiag.Mcp.Diagnostics.Handles;
using WinDiag.Mcp.Diagnostics.Locks;
using WinDiag.Mcp.Diagnostics.Network;
using WinDiag.Mcp.Diagnostics.Pipes;
using WinDiag.Mcp.Diagnostics.Processes;
using WinDiag.Mcp.Diagnostics.RegistryInspection;
using WinDiag.Mcp.Diagnostics.SelfUpdate;
using WinDiag.Mcp.Diagnostics.Services;
using WinDiag.Mcp.Diagnostics.Signatures;
using WinDiag.Mcp.Diagnostics.SystemInfo;
using WinDiag.Mcp.Hosting;
using WinDiag.Mcp.Tools;

namespace WinDiag.Mcp;

/// <summary>Wires up the server's services and tools.</summary>
/// <remarks>
/// Factored out of <c>Program.cs</c> so tests can build the same service graph with fake diagnostics
/// and drive it over an in-memory transport, exercising the real registration path rather than a
/// parallel one that could drift from it.
/// </remarks>
public static class ServerBuilder
{
    /// <summary>Serializer options for every tool; see <see cref="DiagServerKit.ToolJsonOptions"/>.</summary>
    /// <remarks>Kept as an alias, one instance, so the Windows tools and the kit's serialize identically.</remarks>
    internal static readonly JsonSerializerOptions ToolJsonOptions = DiagServerKit.ToolJsonOptions;

    public const string HelpText = """
        windiag - Windows diagnostics MCP server

        Usage:
          WinDiag.Mcp                     Serve MCP over stdio (default).
          WinDiag.Mcp --http <url>        Serve MCP over HTTP, e.g. --http http://10.0.0.5:7777
          WinDiag.Mcp --help              Show this text.

        Running as a Windows service (prompts for elevation if it does not have it):
          WinDiag.Mcp --install-service --http <url> [options]
          WinDiag.Mcp --service-status [--service-name <name>]
          WinDiag.Mcp --uninstall-service [--service-name <name>]

          A service can be restarted remotely with service_control, which a server started by hand
          cannot. Install options:

          --service-name <name>       Default: windiag
          --display-name <text>       What Services.msc shows. Default: the service name
          --start auto|delayed|demand Default: auto
          --account <spec>            LocalSystem (default), NetworkService, LocalService, or
                                      DOMAIN\user with --password
          --password <value>          Required for an account that is not built in
          --token-stdin               Read the token from standard input, so it never appears on
                                      this machine's command line. Needs an elevated terminal
          --token <value>             Default: a new 256-bit token, printed once on success.
                                      Visible in process listings while the installer runs
          --artifacts <dir>           Pin WINDIAG_ARTIFACT_DIR. As SYSTEM, %TEMP% is
                                      C:\Windows\SystemTemp, so captures and dumps move without it
          --allow-self-update         Carry the grants across; a service registered without them
          --allow-command-execution   comes back with fewer tools than the server it replaced
          --allow-arbitrary-write
          --allow-arbitrary-read
          --read-only
          --firewall-from <address>   Allow the bind port inbound from one address, removed on
                                      uninstall. Scoped to an address, never a subnet
          --no-restart-on-failure     Default is to let the SCM restart it if the process dies

          An option not listed here is refused, and nothing is installed.

          The token is written to the service's own registry key, which the installer first restricts
          to SYSTEM and Administrators -- never to a machine-wide variable, which every local user can
          read. The server's own directory and --artifacts are restricted the same way when anyone
          else can write them, because the service runs what it finds there; install from a directory
          of its own, since one that also holds other files is refused instead. A service also checks
          on every start, restricts what it can, and refuses to start from a directory it cannot.

          Each grant flag above becomes its WINDIAG_* variable (below) in that same per-service key:
          --allow-self-update -> WINDIAG_ALLOW_SELF_UPDATE=1, and so on. Flags and variables are two
          spellings of one setting, so anything the environment can express, an install can too.

        Environment:
          WINDIAG_READ_ONLY                       1/true to drop all state-changing tools (default: false)
          WINDIAG_ALLOW_COMMAND_EXECUTION         1/true to register run_command, an arbitrary shell
                                                  as the server's account (default: false; read-only wins)
          WINDIAG_ALLOW_ARBITRARY_WRITE           1/true to let put_file write outside the server's own
                                                  directories (default: false; put_file itself is always
                                                  available on a writable server, scoped to those dirs)
          WINDIAG_ALLOW_ARBITRARY_READ            1/true to let the read tools open files outside those
                                                  directories (default: false). WINDIAG_READ_ONLY does
                                                  NOT override this one -- reading is what a read-only
                                                  server is for, so --read-only --allow-arbitrary-read
                                                  is the deliberate combination for a look-but-do-not-
                                                  touch target
          WINDIAG_ALLOW_SELF_UPDATE               1/true to register update_self, which replaces this
                                                  executable and restarts (default: false)
          WINDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS   Budget per external tool call, 1..3600 (default: 120)
          WINDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS    How long update_self waits for running calls before
                                                  restarting anyway, 1..86400 (default: 1800)
          WINDIAG_MAX_RESULTS                     Row cap per tool call, 1..10000000 (default: 50000)
          WINDIAG_HTTP_BIND                       Address to serve on; same as --http
          WINDIAG_TOKEN                           Bearer token for HTTP. Generated and printed if unset.
          WINDIAG_ARTIFACT_DIR                    Where dumps and traces are written (default: %TEMP%\windiag)

        Started by hand, the server takes --http and nothing else: the grants are WINDIAG_*
        variables, and --read-only or --allow-* on that command line is refused rather than ignored.

        HTTP mode always requires a bearer token. The running server reads it from the environment
        only, never from a command-line argument, because this server's own process_list exposes
        command lines to every local user on the machine. For the same reason the installer takes it
        best through --token-stdin; --token puts it on the installer's command line while it runs.

        Diagnostics are written to stderr. In stdio mode, stdout carries the MCP protocol only.
        """;

    /// <summary>
    /// Registers diagnostics services, the MCP server and its tools, but not a transport.
    /// </summary>
    /// <remarks>
    /// The transport is the caller's choice -- stdio locally, HTTP on a target machine -- and both
    /// paths go through this one method so a tool cannot be registered for one and missed for the
    /// other.
    /// </remarks>
    public static IMcpServerBuilder ConfigureServices(IServiceCollection services, WinDiagOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        services.AddSingleton(options);
        services.AddSingleton(new CommandRunnerOptions(options.ExternalToolTimeout));
        services.TryAddDiagnostics();

        // Lets the same executable run under the Service Control Manager as well as from a terminal.
        //
        // Deliberately additive: this is inert unless the process was actually started as a service, so
        // `WinDiag.Mcp.exe --http ...` in a console and stdio mode behave exactly as before. What
        // it changes when the SCM IS the parent is the three things that would otherwise break -- the
        // lifetime waits on the service stop signal instead of Ctrl-C, the content root becomes the
        // executable's directory instead of System32, and logging goes to the event log, without which a
        // service that fails to start is invisible.
        //
        // Registered here rather than in Program.cs so neither transport can be given it and the other
        // forgotten, which is the same reason the tools are registered here.
        services.AddWindowsService();

        // Immediately after, and not optional. AddWindowsService redirects logging to the event log,
        // which throws if its source is not registered -- and that turned a log line nobody asked for
        // into a failed update_self on a real service. A diagnostic channel must never be able to break
        // the thing it reports on.
        EventLogSink.MakeSafe(services);

        // The surface every server in the family shares -- the two call-tool filters, file transfer and
        // capabilities, the activity tracker and the shutdown window -- registered by the kit in one
        // call. This server's own tools follow, on the builder it returns.
        var files = new FileTransferOptions(
            options.ArtifactDirectory, options.AllowArbitraryWrite, options.AllowArbitraryRead,
            "WINDIAG_ALLOW_ARBITRARY_WRITE=1", "WINDIAG_ALLOW_ARBITRARY_READ=1");
        var update = new SelfUpdateOptions(options.ArtifactDirectory, options.UpdateDrainTimeout);

        var mcp = services
            .AddDiagServer(new DiagServerSettings(options.ReadOnly, files, update), out _)
            .WithTools<FileLockTools>(ToolJsonOptions)
            .WithTools<SystemTools>(ToolJsonOptions)
            .WithTools<ServiceTools>(ToolJsonOptions)
            .WithTools<EventLogTools>(ToolJsonOptions)
            .WithTools<ProcessTools>(ToolJsonOptions)
            .WithTools<InventoryTools>(ToolJsonOptions)
            .WithTools<AccessTools>(ToolJsonOptions)
            .WithTools<ActivityQueryTools>(ToolJsonOptions)
            .WithTools<ModuleTools>(ToolJsonOptions)
            .WithTools<AutostartTools>(ToolJsonOptions)
            .WithTools<RegistryTools>(ToolJsonOptions);

        // Write tools are registered here only when the server is not read-only, so a read-only server
        // does not advertise capabilities it will refuse. capture_dump and capture_activity write files
        // that can be several gigabytes, which is a state change however diagnostic the intent.
        if (!options.ReadOnly)
        {
            mcp.WithTools<DumpTools>(ToolJsonOptions);
            mcp.WithTools<ActivityCaptureTools>(ToolJsonOptions);
            mcp.WithTools<ControlTools>(ToolJsonOptions);

            // put_file is the kit's, and AddDiagServer registers it under the same read-only rule.
        }

        // Gated twice over, and off by default: this one lets the caller replace the server's own
        // elevated binary and run it, which is a different class of authority from anything else here.
        // Read-only still wins -- replacing the binary is the largest change this server can make.
        if (options.AllowSelfUpdate && !options.ReadOnly)
        {
            mcp.WithTools<SelfUpdateTools>(ToolJsonOptions);
        }

        // The heaviest grant of all, and the only tool that is a general shell. Gated behind its own
        // flag and refused under read-only for the same reason update_self is: turning the bearer token
        // into arbitrary code execution on an elevated host is a deliberate per-deployment decision, not
        // something a default server should quietly offer.
        if (options.AllowCommandExecution && !options.ReadOnly)
        {
            mcp.WithTools<CommandTools>(ToolJsonOptions);
        }

        return mcp;
    }

    /// <summary>Registers the diagnostics implementations, leaving any already registered in place.</summary>
    /// <remarks>Tests register fakes first, then call the same wiring, so nothing is special-cased for tests.</remarks>
    private static IServiceCollection TryAddDiagnostics(this IServiceCollection services)
    {
        services.AddSingletonIfMissing<IPrivilegeProbe, WindowsPrivilegeProbe>();
        services.AddSingletonIfMissing<IToolLocator, ToolLocator>();
        services.AddSingletonIfMissing<IExternalToolRunner, ExternalToolRunner>();
        services.AddSingletonIfMissing<ILockInspector, RestartManagerLockInspector>();
        services.AddSingletonIfMissing<IHandleInspector, HandleExeInspector>();
        services.AddSingletonIfMissing<IAutostartInspector, AutorunscInspector>();
        services.AddSingletonIfMissing<ISystemInspector, WindowsSystemInspector>();
        services.AddSingletonIfMissing<ICapabilityRequirements, WindowsCapabilityRequirements>();
        services.AddSingletonIfMissing<IExecutableResolver, SysinternalsExecutableResolver>();
        services.AddSingletonIfMissing<ICapabilityReporter, CapabilityReporter>();
        services.AddSingletonIfMissing<IServiceInspector, WindowsServiceInspector>();
        services.AddSingletonIfMissing<IEventLogInspector, WindowsEventLogInspector>();
        services.AddSingletonIfMissing<IProcessInspector, WmiProcessInspector>();
        services.AddSingletonIfMissing<INamedPipeInspector, NamedPipeInspector>();
        services.AddSingletonIfMissing<INetworkInspector, IpHelperNetworkInspector>();
        services.AddSingletonIfMissing<ISignatureInspector, WinTrustSignatureInspector>();
        services.AddSingletonIfMissing<IAccessInspector, WindowsAccessInspector>();
        services.AddSingletonIfMissing<IRegistryInspector, WindowsRegistryInspector>();
        services.AddSingletonIfMissing<IShellSet, WindowsShellSet>();
        services.AddSingletonIfMissing<ICommandRunner, CommandRunner>();
        services.AddSingletonIfMissing<IDumpWriter, MiniDumpWriter>();
        services.AddSingletonIfMissing<IActivityInspector, ProcmonActivityInspector>();
        services.AddSingletonIfMissing<IStagedBuildInspector, WindowsStagedBuildInspector>();
        services.AddSingletonIfMissing<IUpdateGuard, WindowsSignatureRatchet>();
        services.AddSingletonIfMissing<IRestartHelper, WindowsRestartHelper>();
        services.AddSingletonIfMissing<ISelfUpdater, SelfUpdater>();
        services.AddSingletonIfMissing<Diagnostics.Modules.IModuleInspector, Diagnostics.Modules.WindowsModuleInspector>();
        // Fully qualified: Diagnostics.Control.IServiceController would otherwise collide with
        // System.ServiceProcess.ServiceController, which the services inspector already brings in.
        services.AddSingletonIfMissing<
            Diagnostics.Control.IProcessController, Diagnostics.Control.WindowsProcessController>();
        services.AddSingletonIfMissing<
            Diagnostics.Control.IServiceController, Diagnostics.Control.WindowsServiceControllerAdapter>();
        services.AddSingletonIfMissing<FileLockTools, FileLockTools>();
        services.AddSingletonIfMissing<SystemTools, SystemTools>();
        services.AddSingletonIfMissing<ServiceTools, ServiceTools>();
        services.AddSingletonIfMissing<EventLogTools, EventLogTools>();
        services.AddSingletonIfMissing<ProcessTools, ProcessTools>();
        services.AddSingletonIfMissing<InventoryTools, InventoryTools>();
        services.AddSingletonIfMissing<AccessTools, AccessTools>();
        services.AddSingletonIfMissing<DumpTools, DumpTools>();
        services.AddSingletonIfMissing<ActivityCaptureTools, ActivityCaptureTools>();
        services.AddSingletonIfMissing<ActivityQueryTools, ActivityQueryTools>();
        services.AddSingletonIfMissing<SelfUpdateTools, SelfUpdateTools>();
        services.AddSingletonIfMissing<ControlTools, ControlTools>();
        services.AddSingletonIfMissing<ModuleTools, ModuleTools>();
        services.AddSingletonIfMissing<AutostartTools, AutostartTools>();
        services.AddSingletonIfMissing<RegistryTools, RegistryTools>();
        services.AddSingletonIfMissing<CommandTools, CommandTools>();
        return services;
    }

    private static void AddSingletonIfMissing<TService, TImplementation>(this IServiceCollection services)
        where TService : class
        where TImplementation : class, TService
    {
        if (services.All(descriptor => descriptor.ServiceType != typeof(TService)))
        {
            services.AddSingleton<TService, TImplementation>();
        }
    }
}
