using System.Text.Json;
using System.Text.Json.Serialization;
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
using WinDiag.Mcp.Diagnostics.Files;
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
    /// <summary>
    /// Serializer options for every tool, differing from the SDK's defaults in one respect: a property
    /// whose value is null is written as null rather than omitted.
    /// </summary>
    /// <remarks>
    /// <para>The schema generator marks a constructor parameter required whenever it has no default
    /// value -- nullable or not. (A parameter written <c>= null</c> is marked optional instead, as
    /// <c>LoadedModule.PreferredBase</c> is, which is why that one never broke while <c>Signer</c>
    /// beside it did.) The SDK's default options omit nulls. The two disagree exactly when a required
    /// property is actually null, and the client rejects the response against the schema the server
    /// itself advertised: an unsigned file has no signer, a listening socket has no remote address, an
    /// unlabelled volume has no label. The tool computed the right answer and the caller never saw
    /// it.</para>
    /// <para>Writing nulls satisfies both sides and is set here, once, rather than per property: the
    /// defect is a property of how results are serialized, not of any one model, and forty-odd
    /// attributes are forty-odd chances for the next model to be added without one. It also means
    /// nobody has to audit which parameters happen to carry a default. This is the same fix that
    /// <c>LockHolder</c> carried alone before it was understood to be general.</para>
    /// <para>Note this restores System.Text.Json's own default: <c>Never</c> is the stock value for
    /// <c>DefaultIgnoreCondition</c>, and it is <see cref="McpJsonUtilities.DefaultOptions"/> that opts
    /// into <c>WhenWritingNull</c>. This is a narrower change than "write nulls everywhere" sounds.</para>
    /// <para>Derived from <see cref="McpJsonUtilities.DefaultOptions"/> rather than built fresh, so the
    /// protocol's own converters are kept.</para>
    /// </remarks>
    internal static readonly JsonSerializerOptions ToolJsonOptions =
        new(McpJsonUtilities.DefaultOptions) { DefaultIgnoreCondition = JsonIgnoreCondition.Never };

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
          --token <value>             Default: a new 256-bit token, printed once on success
          --artifacts <dir>           Pin WINDIAG_ARTIFACT_DIR. As SYSTEM, %TEMP% is
                                      C:\Windows\SystemTemp, so captures and dumps move without it
          --allow-self-update         Carry the grants across; a service registered without them
          --allow-command-execution   comes back with fewer tools than the server it replaced
          --read-only
          --firewall-from <address>   Allow the bind port inbound from one address, removed on
                                      uninstall. Scoped to an address, never a subnet
          --no-restart-on-failure     Default is to let the SCM restart it if the process dies

          The token is written to the service's own registry key, which only SYSTEM and
          Administrators can read -- never to a machine-wide variable, which every local user can.

        Environment:
          WINDIAG_READ_ONLY                       1/true to drop all state-changing tools (default: false)
          WINDIAG_ALLOW_COMMAND_EXECUTION         1/true to register run_command, an arbitrary shell
                                                  as the server's account (default: false; read-only wins)
          WINDIAG_ALLOW_ARBITRARY_WRITE           1/true to let put_file write outside the server's own
                                                  directories (default: false; put_file itself is always
                                                  available on a writable server, scoped to those dirs)
          WINDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS   Budget per external tool call, 1..3600 (default: 120)
          WINDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS    How long update_self waits for running calls before
                                                  restarting anyway, 1..86400 (default: 1800)
          WINDIAG_MAX_RESULTS                     Row cap per tool call, 1..10000000 (default: 50000)
          WINDIAG_HTTP_BIND                       Address to serve on; same as --http
          WINDIAG_TOKEN                           Bearer token for HTTP. Generated and printed if unset.
          WINDIAG_ARTIFACT_DIR                    Where dumps and traces are written (default: %TEMP%\windiag)

        HTTP mode always requires a bearer token. The token is read from the environment only, never
        from a command-line argument, because this server's own process_list exposes command lines to
        every local user on the machine.

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
        services.TryAddDiagnostics();

        // Lets the same executable run under the Service Control Manager as well as from a terminal.
        //
        // Deliberately additive: this is inert unless the process was actually started as a service, so
        // `WinDiag.Mcp.exe --http ...` in a console and the stdio relay behave exactly as before. What
        // it changes when the SCM IS the parent is the three things that would otherwise break -- the
        // lifetime waits on the service stop signal instead of Ctrl-C, the content root becomes the
        // executable's directory instead of System32, and logging goes to the event log, without which a
        // service that fails to start is invisible.
        //
        // Registered here rather than in Program.cs so neither transport can be given it and the other
        // forgotten, which is the same reason the tools are registered here.
        services.AddWindowsService();

        // Shared by the gate below and by SelfUpdater, so the update waits on the same count the
        // filter maintains. Constructed here rather than resolved, because a request filter closure has
        // no service provider; a fresh instance per call keeps tests isolated from each other.
        var activity = new ToolActivity();
        services.AddSingleton(activity);

        // Pinned rather than inherited. This is the window the host allows for in-flight work to stop
        // once shutdown begins, and the default happened to be 30s -- which is what truncated a
        // 90-second capture during an update. An ordinary update no longer reaches it, because the drain
        // waits for the server to be idle first; it still applies when that drain hits its own budget,
        // and on the forced path, where it is the time in which capture_activity's cancellation kills
        // Procmon. Shortening it would trade a truncated capture for an orphaned kernel driver.
        services.Configure<HostOptions>(host => host.ShutdownTimeout = TimeSpan.FromSeconds(30));

        var mcp = services
            .AddMcpServer()

            // Before any tool: a refusal the caller cannot read is a refusal they will retry into.
            .WithReadableToolErrors()

            // Counts what is running, so update_self can wait for it instead of cutting it off.
            .WithToolActivityGate(activity)
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
            .WithTools<RegistryTools>(ToolJsonOptions)

            // Read side of the transfer, so it stays available on a read-only server: collecting a dump
            // or a trace off a machine is exactly what someone pointed at one is doing, and the directory
            // confinement -- not the mode -- is what bounds it. WINDIAG_ALLOW_ARBITRARY_READ only widens
            // WHERE it may read, and is enforced per-call.
            .WithTools<FileReadTools>(ToolJsonOptions);

        // Write tools are registered here only when the server is not read-only, so a read-only server
        // does not advertise capabilities it will refuse. capture_dump and capture_activity write files
        // that can be several gigabytes, which is a state change however diagnostic the intent.
        if (!options.ReadOnly)
        {
            mcp.WithTools<DumpTools>(ToolJsonOptions);
            mcp.WithTools<ActivityCaptureTools>(ToolJsonOptions);
            mcp.WithTools<ControlTools>(ToolJsonOptions);

            // Always available on a writable server, not behind a flag: confined to windiag's own
            // directories it grants nothing SMB-to-those-folders plus update_self did not already, and
            // its whole purpose is to remove SMB from the staging loop. The WINDIAG_ALLOW_ARBITRARY_WRITE
            // flag only widens WHERE it may write, and is enforced per-call, not here.
            mcp.WithTools<FileTools>(ToolJsonOptions);
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
        services.AddSingletonIfMissing<ICapabilityReporter, CapabilityReporter>();
        services.AddSingletonIfMissing<IServiceInspector, WindowsServiceInspector>();
        services.AddSingletonIfMissing<IEventLogInspector, WindowsEventLogInspector>();
        services.AddSingletonIfMissing<IProcessInspector, WmiProcessInspector>();
        services.AddSingletonIfMissing<INamedPipeInspector, NamedPipeInspector>();
        services.AddSingletonIfMissing<INetworkInspector, IpHelperNetworkInspector>();
        services.AddSingletonIfMissing<ISignatureInspector, WinTrustSignatureInspector>();
        services.AddSingletonIfMissing<IAccessInspector, WindowsAccessInspector>();
        services.AddSingletonIfMissing<IRegistryInspector, WindowsRegistryInspector>();
        services.AddSingletonIfMissing<ICommandRunner, WindowsCommandRunner>();
        services.AddSingletonIfMissing<IFileReceiver, WindowsFileReceiver>();
        services.AddSingletonIfMissing<IFileSender, WindowsFileSender>();
        services.AddSingletonIfMissing<IDumpWriter, MiniDumpWriter>();
        services.AddSingletonIfMissing<IActivityInspector, ProcmonActivityInspector>();
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
        services.AddSingletonIfMissing<FileTools, FileTools>();
        services.AddSingletonIfMissing<FileReadTools, FileReadTools>();
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
