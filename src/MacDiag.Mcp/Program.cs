using Diag.Mcp.Server;
using MacDiag.Mcp;
using MacDiag.Mcp.Configuration;
using MacDiag.Mcp.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

if (args.Any(a => a is "--help" or "-h"))
{
    Console.Error.WriteLine(ServerBuilder.HelpText);
    return 0;
}

// Said plainly rather than left to fail on the first sysctl: the assembly is macOS-only, and a copy started
// on the wrong machine should say which binary it wanted.
if (!OperatingSystem.IsMacOS())
{
    Console.Error.WriteLine("[macdiag] this server runs on macOS only; on Windows use WinDiag.Mcp, on Linux LinuxDiag.Mcp.");
    return 2;
}

if (args.Any(a => a is "--install-service" or "--uninstall-service" or "--service-status"))
{
    Console.Error.WriteLine("[macdiag] service management arrives with the launchd installer.");
    return 2;
}

MacDiagOptions options;
string? bind;
try
{
    var environment = Environment.GetEnvironmentVariables();
    if (ArgumentValue(args, "--env-file") is { } envFile)
    {
        environment = EnvFile.Over(environment, ReadEnvFile(envFile));
    }

    options = MacDiagOptions.FromEnvironment(environment);
    bind = HttpBind.Resolve(args, options.HttpBind, "MACDIAG_HTTP_BIND");
}
catch (ConfigurationException ex)
{
    // Under launchd a non-zero exit is restarted every 10 s (its throttle), each attempt writing this line to
    // crash.log; the daemon then recovers by itself once the file is fixed.
    Console.Error.WriteLine($"[macdiag] configuration error: {ex.Message}");
    return 2;
}

return bind is null
    ? await RunStdio(options).ConfigureAwait(false)
    : await RunHttp(options, bind).ConfigureAwait(false);

// Checked before a byte is read: a token file another account could write is a planted token. Every failure
// becomes a configuration error naming the file, never a crash with a stack trace.
static IReadOnlyDictionary<string, string> ReadEnvFile(string path)
{
    try
    {
        StartupPermissions.Require(path, Environment.ProcessPath);
        return EnvFile.Parse(File.ReadAllText(path));
    }
    catch (Exception ex) when (ex is ExternalCommandException or IOException or UnauthorizedAccessException or FormatException)
    {
        throw new ConfigurationException($"Could not read the settings file '{path}': {ex.Message}");
    }
}

static string? ArgumentValue(string[] arguments, string name)
{
    var index = Array.IndexOf(arguments, name);
    return index >= 0 && index + 1 < arguments.Length ? arguments[index + 1] : null;
}

async Task<int> RunStdio(MacDiagOptions opts)
{
    // The server's own directory as content root, as DiagServerHost does for HTTP: launchd starts daemons in /.
    var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { ContentRootPath = AppContext.BaseDirectory });
    ConfigureLogging(builder.Logging);
    ServerBuilder.ConfigureServices(builder.Services, opts).WithStdioServerTransport();

    var host = builder.Build();
    Log(host.Services, $"starting stdio server ({opts.Describe()})");
    await host.RunAsync().ConfigureAwait(false);
    return 0;
}

async Task<int> RunHttp(MacDiagOptions opts, string address)
{
    var token = opts.Token ?? BearerTokenGate.GenerateToken();
    opts = opts with { HttpBind = address };

    return await DiagServerHost.RunHttpAsync(
        new HttpHostSettings(address, opts.Token, "[macdiag]", "MACDIAG_TOKEN", token),
        builder =>
        {
            ConfigureLogging(builder.Logging);
            ServerBuilder.ConfigureServices(builder.Services, opts).WithHttpTransport();
        },
        afterBanner: app => Log(app.Services, $"starting http server ({opts.Describe()})")).ConfigureAwait(false);
}

// stdout is the MCP channel in stdio mode, so every log line goes to stderr.
void ConfigureLogging(ILoggingBuilder logging)
{
    logging.ClearProviders();
    logging.AddConsole(consoleOptions => consoleOptions.LogToStandardErrorThreshold = LogLevel.Trace);
}

void Log(IServiceProvider services, string message) =>
    services.GetRequiredService<ILoggerFactory>().CreateLogger("macdiag").LogInformation("{Message}", message);
