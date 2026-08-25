using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinDiag.Mcp;
using WinDiag.Mcp.Configuration;
using WinDiag.Mcp.Hosting;

if (args.Any(a => a is "--help" or "-h" or "/?"))
{
    Console.Error.WriteLine(ServerBuilder.HelpText);
    return 0;
}

// Relay mode: a local stdio server that forwards to whichever target windiag it is pointed at, so one
// fixed MCP registration reaches any target at a runtime-chosen address. It is a client of the real
// servers, not a diagnostics server itself, so it shares none of the tool wiring below.
if (args.Any(a => a is "--relay"))
{
    return await WinDiag.Mcp.Relay.RelayServer.RunAsync(defaultPort: 4024).ConfigureAwait(false);
}

// Service management: sets this machine up from the one file that is already on it, and never starts
// a server. Handled before the options below because these switches configure the environment the
// service will get rather than reading the one this process happens to have -- an install run from a
// terminal with no WINDIAG_TOKEN set must still be able to register a service that has one.
if (args.Any(a => a is "--install-service" or "--uninstall-service" or "--service-status"))
{
    try
    {
        // The SCM refuses an unelevated caller, so ask Windows rather than failing at the first
        // sc.exe call with an access-denied nobody can act on.
        if (!ServiceInstaller.IsElevated())
        {
            Console.Error.WriteLine("[windiag] this needs administrator rights; requesting elevation...");
            return ServiceInstaller.RelaunchElevated(args);
        }

        if (args.Any(a => a is "--service-status"))
        {
            return ServiceInstaller.Status(ServiceName(args));
        }

        if (args.Any(a => a is "--uninstall-service"))
        {
            return ServiceInstaller.Uninstall(
                new ServiceInstallOptions { Name = ServiceName(args), Bind = "http://unused", Token = "unused" });
        }

        return ServiceInstaller.Install(ServiceInstallOptions.Parse(args));
    }
    catch (ConfigurationException ex)
    {
        Console.Error.WriteLine($"[windiag] {ex.Message}");
        return 2;
    }
    catch (Exception ex)
    {
        // The installer is the one command whose audience is a person at a console who has not yet got
        // a working server, so a raw unhandled stack trace is the least useful thing it can print. It
        // printed one once -- a missing assembly deep inside EventLog -- and read as "the tool is
        // broken" rather than "this step failed". Name the type, because whoever sees this is the only
        // one who can report it.
        Console.Error.WriteLine($"[windiag] service management failed: {ex.GetType().FullName}: {ex.Message}");

        // Only install can leave a half-registered service behind, so only install gets told to clean
        // one up. Printing that after a failed --service-status would be advice to uninstall a service
        // because reading it went wrong.
        Console.Error.WriteLine(args.Any(a => a is "--install-service")
            ? "[windiag] run --service-status to see how far this got; a service that was created but "
              + "not configured must be removed with --uninstall-service before retrying."
            : "[windiag] nothing was changed by this command.");

        return 4;
    }
}

static string ServiceName(string[] arguments)
{
    for (var i = 0; i < arguments.Length - 1; i++)
    {
        if (string.Equals(arguments[i], "--service-name", StringComparison.OrdinalIgnoreCase))
        {
            return arguments[i + 1];
        }
    }

    return "windiag";
}

WinDiagOptions options;
string? bind;
try
{
    options = WinDiagOptions.FromEnvironment();
    bind = CommandLine.ResolveHttpBind(args, options);
}
catch (ConfigurationException ex)
{
    // Fail at startup rather than on the first tool call: a misconfigured server that answers
    // questions is worse than one that refuses to start.
    Console.Error.WriteLine($"[windiag] configuration error: {ex.Message}");
    return 2;
}

return bind is null
    ? await RunStdio(options).ConfigureAwait(false)
    : await RunHttp(options, bind).ConfigureAwait(false);

async Task<int> RunStdio(WinDiagOptions opts)
{
    var builder = Host.CreateApplicationBuilder();
    ConfigureLogging(builder.Logging);

    ServerBuilder.ConfigureServices(builder.Services, opts).WithStdioServerTransport();

    var host = builder.Build();
    WarnIfMisdeployed();
    Log(host.Services, $"starting stdio server ({opts.Describe()})");

    await host.RunAsync().ConfigureAwait(false);
    return 0;
}

async Task<int> RunHttp(WinDiagOptions opts, string address)
{
    // Generated rather than refused when unset: an unauthenticated endpoint must not be reachable,
    // but making the operator invent a token before the server will start only encourages weak ones.
    var token = opts.Token ?? BearerTokenGate.GenerateToken();

    // Record the address that was actually resolved, so the startup audit line reflects reality
    // rather than reporting stdio while a TCP port is open.
    opts = opts with { HttpBind = address };

    var builder = WebApplication.CreateBuilder();
    ConfigureLogging(builder.Logging);

    // Kestrel caps request bodies at 30 MB by default, which would reject a put_file carrying a
    // base64'd server binary (~64 MB encoded). Raised to sit above put_file's own 128 MB decoded limit
    // plus base64 inflation, so the tool -- not the transport -- gives the size error, with a message
    // that names the cap. Configured through DI rather than builder.WebHost.ConfigureKestrel to avoid
    // depending on the hosting extension namespace.
    builder.Services.Configure<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>(
        kestrel => kestrel.Limits.MaxRequestBodySize = 220L * 1024 * 1024);

    ServerBuilder.ConfigureServices(builder.Services, opts).WithHttpTransport();

    var app = builder.Build();
    app.UseMiddleware<BearerTokenGate>(token);
    app.MapMcp();

    WarnIfMisdeployed();
    Console.Error.WriteLine($"[windiag] serving MCP over HTTP on {address}");

    // Printed only when generated. Echoing a configured token would put a long-lived credential into
    // whatever captures stderr -- and running an elevated listener under a service wrapper with
    // `2> windiag.log` is the normal way to do this, so that file is the expected case, not the
    // exotic one.
    if (opts.Token is null)
    {
        Console.Error.WriteLine($"[windiag] generated bearer token: {token}");
        Console.Error.WriteLine(
            "[windiag] this token was generated for this run and changes on restart. " +
            "Set WINDIAG_TOKEN to pin it.");
    }
    else
    {
        Console.Error.WriteLine("[windiag] bearer token: taken from WINDIAG_TOKEN (not logged)");
    }

    if (CommandLine.IsWildcardBind(address))
    {
        Console.Error.WriteLine(
            "[windiag] WARNING: this address accepts connections on every network interface. " +
            "This process is elevated, so anyone who reaches the port and holds the token can run " +
            "commands as the current account. Scope the firewall rule to the base machine's address, " +
            "or bind to a specific interface.");
    }

    Log(app.Services, $"starting http server ({opts.Describe()})");

    await app.RunAsync(address).ConfigureAwait(false);
    return 0;
}

// stdout is the MCP JSON-RPC channel in stdio mode. A single log line written there corrupts the
// protocol stream, so every provider is cleared and the console logger is pinned to stderr at all
// levels. HTTP mode keeps the same arrangement so both transports behave identically.
void ConfigureLogging(ILoggingBuilder logging)
{
    logging.ClearProviders();
    logging.AddConsole(consoleOptions => consoleOptions.LogToStandardErrorThreshold = LogLevel.Trace);
}

// Surfaced at startup as well as in system_overview, because the consequences (no 64-bit dumps, no
// activity capture) only show up much later and look like tool failures rather than a wrong build.
void WarnIfMisdeployed()
{
    if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
    {
        Console.Error.WriteLine(
            "[windiag] WARNING: this is the win-x86 build running on 64-bit Windows. Deploy the win-x64 " +
            "build here; the 32-bit one cannot dump 64-bit processes or capture activity on this OS.");
    }
}

void Log(IServiceProvider services, string message) =>
    services.GetRequiredService<ILoggerFactory>().CreateLogger("windiag").LogInformation("{Message}", message);
