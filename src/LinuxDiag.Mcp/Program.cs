using Diag.Mcp.Server;
using LinuxDiag.Mcp;
using LinuxDiag.Mcp.Configuration;
using LinuxDiag.Mcp.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

if (args.Any(a => a is "--help" or "-h"))
{
    Console.Error.WriteLine(ServerBuilder.HelpText);
    return 0;
}

// Said plainly rather than left to fail on the first /proc read: the assembly is Linux-only, and a
// copy started on the wrong machine should say which binary it wanted.
if (!OperatingSystem.IsLinux())
{
    Console.Error.WriteLine("[linuxdiag] this server runs on Linux only; on Windows use WinDiag.Mcp.");
    return 2;
}

// Service management: sets this machine up from the one file already on it, and never starts a server.
// Handled before the options below because these switches configure the environment the service will
// get, not the one this process happens to have.
if (args.Any(a => a is "--install-service" or "--uninstall-service" or "--service-status"))
{
    try
    {
        if (!Environment.IsPrivilegedProcess)
        {
            Console.Error.WriteLine("[linuxdiag] service management needs root; run it with sudo.");
            return 2;
        }

        var name = LinuxServiceInstallOptions.ServiceName(args);
        if (args.Contains("--service-status"))
        {
            return LinuxServiceInstaller.Status(name);
        }

        return args.Contains("--uninstall-service")
            ? LinuxServiceInstaller.Uninstall(name)
            : LinuxServiceInstaller.Install(LinuxServiceInstallOptions.Parse(args));
    }
    catch (ConfigurationException ex)
    {
        Console.Error.WriteLine($"[linuxdiag] {ex.Message}");
        return 2;
    }
    catch (Exception ex)
    {
        // The installer's audience is a person at a console without a working server yet, so a raw stack
        // trace is the least useful thing it could print. Name the type; they are the one who can report it.
        Console.Error.WriteLine($"[linuxdiag] service management failed: {ex.GetType().FullName}: {ex.Message}");
        return 4;
    }
}

LinuxDiagOptions options;
string? bind;
try
{
    options = LinuxDiagOptions.FromEnvironment();
    bind = HttpBind.Resolve(args, options.HttpBind, "LINUXDIAG_HTTP_BIND");
}
catch (ConfigurationException ex)
{
    Console.Error.WriteLine($"[linuxdiag] configuration error: {ex.Message}");
    return 2;
}

return bind is null
    ? await RunStdio(options).ConfigureAwait(false)
    : await RunHttp(options, bind).ConfigureAwait(false);

async Task<int> RunStdio(LinuxDiagOptions opts)
{
    var builder = Host.CreateApplicationBuilder();
    ConfigureLogging(builder.Logging);
    ServerBuilder.ConfigureServices(builder.Services, opts).WithStdioServerTransport();

    var host = builder.Build();
    Log(host.Services, $"starting stdio server ({opts.Describe()})");
    await host.RunAsync().ConfigureAwait(false);
    return 0;
}

async Task<int> RunHttp(LinuxDiagOptions opts, string address)
{
    var token = opts.Token ?? BearerTokenGate.GenerateToken();
    opts = opts with { HttpBind = address };

    return await DiagServerHost.RunHttpAsync(
        new HttpHostSettings(address, opts.Token, "[linuxdiag]", "LINUXDIAG_TOKEN", token),
        builder =>
        {
            ConfigureLogging(builder.Logging);
            ServerBuilder.ConfigureServices(builder.Services, opts).WithHttpTransport();
        },
        afterBanner: app => Log(app.Services, $"starting http server ({opts.Describe()})")).ConfigureAwait(false);
}

// stdout is the MCP channel in stdio mode, so every log line goes to stderr -- which systemd sends to
// the journal when running as a service.
void ConfigureLogging(ILoggingBuilder logging)
{
    logging.ClearProviders();
    logging.AddConsole(consoleOptions => consoleOptions.LogToStandardErrorThreshold = LogLevel.Trace);
}

void Log(IServiceProvider services, string message) =>
    services.GetRequiredService<ILoggerFactory>().CreateLogger("linuxdiag").LogInformation("{Message}", message);
