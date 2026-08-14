using Microsoft.Extensions.DependencyInjection;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Diagnostics;
using WinDiag.Mcp.Diagnostics.Access;
using WinDiag.Mcp.Diagnostics.Activity;
using WinDiag.Mcp.Diagnostics.Autostart;
using WinDiag.Mcp.Diagnostics.Capabilities;
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
    public const string HelpText = """
        windiag - Windows diagnostics MCP server

        Usage:
          WinDiag.Mcp                     Serve MCP over stdio (default).
          WinDiag.Mcp --http <url>        Serve MCP over HTTP, e.g. --http http://10.0.0.5:7777
          WinDiag.Mcp --help              Show this text.

        Environment:
          WINDIAG_READ_ONLY                       1/true to drop all state-changing tools (default: false)
          WINDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS   Budget per external tool call, 1..3600 (default: 120)
          WINDIAG_MAX_RESULTS                     Row cap per tool call, 1..10000 (default: 200)
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

        var mcp = services
            .AddMcpServer()

            // Before any tool: a refusal the caller cannot read is a refusal they will retry into.
            .WithReadableToolErrors()
            .WithTools<FileLockTools>()
            .WithTools<SystemTools>()
            .WithTools<ServiceTools>()
            .WithTools<EventLogTools>()
            .WithTools<ProcessTools>()
            .WithTools<InventoryTools>()
            .WithTools<AccessTools>()
            .WithTools<ActivityQueryTools>()
            .WithTools<ModuleTools>()
            .WithTools<AutostartTools>()
            .WithTools<RegistryTools>();

        // Write tools are registered here only when the server is not read-only, so a read-only server
        // does not advertise capabilities it will refuse. capture_dump and capture_activity write files
        // that can be several gigabytes, which is a state change however diagnostic the intent.
        if (!options.ReadOnly)
        {
            mcp.WithTools<DumpTools>();
            mcp.WithTools<ActivityCaptureTools>();
            mcp.WithTools<ControlTools>();
        }

        // Gated twice over, and off by default: this one lets the caller replace the server's own
        // elevated binary and run it, which is a different class of authority from anything else here.
        // Read-only still wins -- replacing the binary is the largest change this server can make.
        if (options.AllowSelfUpdate && !options.ReadOnly)
        {
            mcp.WithTools<SelfUpdateTools>();
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
