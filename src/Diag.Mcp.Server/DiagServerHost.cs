using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace Diag.Mcp.Server;

/// <summary>How a server is served over HTTP, and how it speaks to its operator while starting.</summary>
/// <param name="Address">The resolved bind address, e.g. http://10.0.0.5:4024.</param>
/// <param name="ConfiguredToken">The token from the environment, or null when one was generated.</param>
/// <param name="LogPrefix">"[windiag]", "[linuxdiag]" or "[macdiag]", per server; every line printed carries it.</param>
/// <param name="TokenVariable">The variable named when telling the operator how to pin a token.</param>
/// <param name="ResolvedToken">The token actually enforced: the configured one, or a generated one.</param>
public sealed record HttpHostSettings(
    string Address, string? ConfiguredToken, string LogPrefix, string TokenVariable, string ResolvedToken);

/// <summary>Serves a diagnostics server over bearer-authenticated HTTP, as the relay expects.</summary>
public static class DiagServerHost
{
    /// <summary>Builds the application with the gate and the MCP endpoint, without starting it.</summary>
    /// <remarks>
    /// MCP is mapped at the root path because that is the relay's contract: it passes the URL through
    /// unchanged, and the docs and the targets file use bare base URLs. Split from
    /// <see cref="RunHttpAsync"/> so a test can start the real host on an ephemeral port.
    /// </remarks>
    public static WebApplication BuildHttp(HttpHostSettings settings, Action<WebApplicationBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(configure);

        // The server's own directory, never the working directory. systemd starts a service in /, and a
        // content root of / stalled host startup before a single line was logged -- the unit sat in
        // 'activating' until systemd killed it. Nothing here reads files from the content root, so
        // pinning it costs nothing wherever the process is started from.
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = AppContext.BaseDirectory });
        builder.WebHost.UseUrls(settings.Address);

        // Kestrel caps request bodies at 30 MB by default, which would reject a put_file carrying a
        // base64'd server binary (~64 MB encoded). Raised to sit above put_file's own 128 MB decoded limit
        // plus base64 inflation, so the tool -- not the transport -- gives the size error, with a message
        // that names the cap.
        builder.Services.Configure<KestrelServerOptions>(
            kestrel => kestrel.Limits.MaxRequestBodySize = 220L * 1024 * 1024);

        // The gate's clock; a test registers its own in configure, which wins.
        builder.Services.TryAddSingleton(TimeProvider.System);

        configure(builder);

        // After configure, so every server gets it whatever providers it chose. ASP.NET Core writes "Request starting"
        // and "Request finished" at Information for every request, the ones the gate turns away included: anyone who
        // can reach the port could roll MacDiag's log or exhaust journald's rate limit without a token. Its warnings and
        // errors still come through, and who was turned away is the gate's to say (RejectedRequestLog).
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);

        var app = builder.Build();
        app.UseMiddleware<BearerTokenGate>(settings.ResolvedToken);
        app.MapMcp();
        return app;
    }

    /// <summary>Builds, prints the operator banner, and serves until shutdown.</summary>
    /// <param name="beforeBanner">Server-specific warnings that belong ahead of the banner.</param>
    /// <param name="afterBanner">Server-specific startup logging, once the application exists.</param>
    public static async Task<int> RunHttpAsync(
        HttpHostSettings settings,
        Action<WebApplicationBuilder> configure,
        Action<WebApplication>? beforeBanner = null,
        Action<WebApplication>? afterBanner = null)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var app = BuildHttp(settings, configure);
        var prefix = settings.LogPrefix;

        beforeBanner?.Invoke(app);
        Console.Error.WriteLine($"{prefix} serving MCP over HTTP on {settings.Address}");

        // Printed only when generated. Echoing a configured token would put a long-lived credential into
        // whatever captures stderr -- and running an elevated listener under a service wrapper with
        // `2> server.log` is the normal way to do this, so that file is the expected case, not the
        // exotic one.
        if (settings.ConfiguredToken is null)
        {
            Console.Error.WriteLine($"{prefix} generated bearer token: {settings.ResolvedToken}");
            Console.Error.WriteLine(
                $"{prefix} this token was generated for this run and changes on restart. " +
                $"Set {settings.TokenVariable} to pin it.");
        }
        else
        {
            Console.Error.WriteLine($"{prefix} bearer token: taken from {settings.TokenVariable} (not logged)");
        }

        if (HttpBind.IsWildcard(settings.Address))
        {
            Console.Error.WriteLine(
                $"{prefix} WARNING: this address accepts connections on every network interface. " +
                "This process is elevated, so anyone who reaches the port and holds the token can run " +
                "commands as the current account. Scope the firewall rule to the base machine's address, " +
                "or bind to a specific interface.");
        }

        afterBanner?.Invoke(app);

        await app.RunAsync(settings.Address).ConfigureAwait(false);
        return 0;
    }
}
