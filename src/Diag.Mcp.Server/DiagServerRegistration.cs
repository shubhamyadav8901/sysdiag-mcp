using Diag.Mcp.Server.Capabilities;
using Diag.Mcp.Server.Files;
using Diag.Mcp.Server.SelfUpdate;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Diag.Mcp.Server;

/// <summary>What the kit needs to register a server's shared surface.</summary>
/// <param name="ReadOnly">When true, <c>put_file</c> is not registered at all.</param>
public sealed record DiagServerSettings(bool ReadOnly, FileTransferOptions Files, SelfUpdateOptions Update);

/// <summary>Registers everything a diagnostics server in this family shares.</summary>
/// <remarks>
/// <para>Implementations are added with TryAdd, so a server's own -- and a test's fakes, registered
/// first -- win. What the kit cannot know, the server supplies before or after this call: an
/// <see cref="ICapabilityReporter"/> with its table, an <see cref="IPrivilegeProbe"/>, and the engines'
/// per-platform halves.</para>
/// <para>The server then adds its own tools to the builder this returns, including its
/// <c>update_self</c> and <c>run_command</c> tool classes behind its own grants: their descriptions and
/// defaults name that platform's shells and file names, which are compile-time text.</para>
/// </remarks>
public static class DiagServerRegistration
{
    public static IMcpServerBuilder AddDiagServer(
        this IServiceCollection services, DiagServerSettings settings, out ToolActivity activity)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(settings);

        services.TryAddSingleton(settings.Files);
        services.TryAddSingleton(settings.Update);
        services.TryAddSingleton<IFileReceiver, FileReceiver>();
        services.TryAddSingleton<IFileSender, FileSender>();
        services.TryAddSingleton<CapabilityTools>();
        services.TryAddSingleton<FileTools>();
        services.TryAddSingleton<FileReadTools>();

        // Shared by the gate below and by SelfUpdater, so the update waits on the same count the
        // filter maintains. Constructed here rather than resolved, because a request filter closure has
        // no service provider; a fresh instance per call keeps tests isolated from each other.
        activity = new ToolActivity();
        services.AddSingleton(activity);

        // Pinned rather than inherited. This is the window the host allows for in-flight work to stop
        // once shutdown begins, and the default happened to be 30s -- which is what truncated a
        // 90-second capture during an update. An ordinary update no longer reaches it, because the drain
        // waits for the server to be idle first; it still applies when that drain hits its own budget,
        // and on the forced path, where it is the time in which a capture's cancellation stops its
        // child tools. Shortening it would trade a truncated capture for an orphaned driver.
        services.Configure<HostOptions>(host => host.ShutdownTimeout = TimeSpan.FromSeconds(30));

        var mcp = services
            .AddMcpServer()

            // Before any tool: a refusal the caller cannot read is a refusal they will retry into.
            .WithReadableToolErrors()

            // Counts what is running, so update_self can wait for it instead of cutting it off.
            .WithToolActivityGate(activity)
            .WithTools<CapabilityTools>(DiagServerKit.ToolJsonOptions)

            // Read side of the transfer, so it stays available on a read-only server: collecting a dump
            // or a trace off a machine is exactly what someone pointed at one is doing, and the directory
            // confinement -- not the mode -- is what bounds it. The arbitrary-read grant only widens
            // WHERE it may read, and is enforced per-call.
            .WithTools<FileReadTools>(DiagServerKit.ToolJsonOptions);

        // Only when the server is not read-only, so a read-only server does not advertise a capability
        // it will refuse. Not behind a flag otherwise: confined to the server's own directories it grants
        // nothing the server's own update path did not already, and the arbitrary-write grant only
        // widens WHERE it may write, enforced per-call, not here.
        if (!settings.ReadOnly)
        {
            mcp.WithTools<FileTools>(DiagServerKit.ToolJsonOptions);
        }

        return mcp;
    }
}
